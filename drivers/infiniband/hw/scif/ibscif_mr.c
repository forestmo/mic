/*
 * Copyright (c) 2008 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the
 * GNU General Public License (GPL) Version 2, available from the
 * file COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "ibscif_driver.h"

static int ibscif_mr_init_mreg(struct ibscif_mr *mr);

struct ib_mr *ibscif_get_dma_mr(struct ib_pd *ibpd, int access)
{
	struct ibscif_dev *dev = to_dev(ibpd->device);
	struct ibscif_mr *mr;
	int err;

	if (!atomic_add_unless(&dev->mr_cnt, 1, MAX_MRS))
		return ERR_PTR(-EAGAIN);

	mr = kzalloc(sizeof *mr, GFP_KERNEL);
	if (!mr) {
		err = -ENOMEM;
		printk(KERN_ALERT PFX "%s: unable to allocate mr.\n", __func__);
		goto out1;
	}

	kref_init(&mr->ref);
	init_completion(&mr->done);

	err = ibscif_wiremap_add(mr, &mr->ibmr.lkey);
	if (err) {
		printk(KERN_ALERT PFX "%s: unable to allocate lkey.\n",
			__func__);
		goto out2;
	}

	if (mr->ibmr.lkey > IBSCIF_MR_MAX_KEY) {
		err = -ENOSPC;
		printk(KERN_ALERT PFX "%s: lkey (%x) out of range.\n",
			__func__, mr->ibmr.lkey);
		goto out3;
	}

	mr->ibmr.device = ibpd->device;
	mr->ibmr.rkey	= mr->ibmr.lkey;
	mr->access	= access;
	mr->magic	= MR_MAGIC;
	INIT_LIST_HEAD(&mr->mreg_list);

	return &mr->ibmr;

out3:
	ibscif_wiremap_del(mr->ibmr.lkey);
out2:
	kfree(mr);
out1:
	atomic_dec(&dev->mr_cnt);
	return ERR_PTR(err);
}

struct ib_mr *ibscif_reg_phys_mr(struct ib_pd *ibpd,
				 struct ib_phys_buf *phys_buf_array,
				 int num_phys_buf, int access,
				 u64 *iova_start)
{
	struct ibscif_mr *mr;
	struct ib_mr *ibmr;
	int i, j, k, n, err;
	u64 mask;

	ibmr = ibscif_get_dma_mr(ibpd, access);
	if (IS_ERR(ibmr))
		return ibmr;

	mr = to_mr(ibmr);
	mr->addr = *iova_start;

	mask = 0;
	for (i = 0; i < num_phys_buf; i++) {
		 /* All but the first buffer must be page aligned */
		if (i != 0)
			mask |= phys_buf_array[i].addr;

		 /* All but the last buffer must end at page boundary */
		if (i != num_phys_buf - 1)
			mask |= phys_buf_array[i].addr + phys_buf_array[i].size;

		mr->length += phys_buf_array[i].size;
	}
	if ((mask & ~PAGE_MASK) || (mr->length > MAX_MR_SIZE)) {
		err = -EINVAL;
		goto out;
	}
	if (mr->length && ((mr->addr + mr->length - 1) < mr->addr)) {
		err = -EOVERFLOW;
		goto out;
	}

	phys_buf_array[0].size += phys_buf_array[0].addr & ~PAGE_MASK;
	phys_buf_array[0].addr &= PAGE_MASK;

	for (i = 0; i < num_phys_buf; i++)
		mr->npages += PAGE_ALIGN(phys_buf_array[i].size) >> PAGE_SHIFT;

	if (!mr->npages)
		return &mr->ibmr;

	err = ibscif_reserve_quota(&mr->npages);
	if (err)
		goto out;

	mr->page = vzalloc(mr->npages * sizeof *mr->page);
	if (!mr->page) {
		err = -ENOMEM;
		goto out;
	}

	k = 0;
	for (i = 0; i < num_phys_buf; i++) {
		n = PAGE_ALIGN(phys_buf_array[i].size) >> PAGE_SHIFT;
		for (j = 0; j < n; j++)
			mr->page[k++] = pfn_to_page((phys_buf_array[i].addr
						     >> PAGE_SHIFT) + j);
	}

	return &mr->ibmr;
out:
	ibscif_dereg_mr(ibmr);
	return ERR_PTR(err);
}

struct ib_mr *ibscif_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 length,
				 u64 virt_addr, int access,
				 struct ib_udata *udata)
{
	struct ib_mr *ibmr;
	struct ibscif_mr *mr;
	struct scatterlist *sg;
	struct ibscif_dev *dev;
	int i, k, err;

	if (length && ((start + length - 1) < start))
		return ERR_PTR(-EOVERFLOW);

	ibmr = ibscif_get_dma_mr(ibpd, access);
	if (IS_ERR(ibmr))
		return ibmr;

	mr = to_mr(ibmr);
	mr->addr = start;

	mr->umem = ib_umem_get(ibpd->uobject->context, start, length,
			       access, 0/*dma_sync*/);
	if (IS_ERR(mr->umem)) {
		err = PTR_ERR(mr->umem);
		printk(KERN_ALERT PFX "%s: ib_umem_get returns %d.\n",
			__func__, err);
		goto out;
	}

	mr->npages = ib_umem_page_count(mr->umem);
	if (!mr->npages)
		return &mr->ibmr;

	mr->length = mr->umem->length;

	err = ibscif_reserve_quota(&mr->npages);
	if (err)
		goto out;

	mr->page = vzalloc(mr->npages * sizeof *mr->page);
	if (!mr->page) {
		err = -ENOMEM;
		printk(KERN_ALERT PFX "%s: unable to allocate mr->page.\n",
			__func__);
		goto out;
	}

	k = 0;
	for_each_sg(mr->umem->sg_head.sgl, sg, mr->umem->nmap, i)
		mr->page[k++] = sg_page(sg);

	err = ibscif_mr_init_mreg(mr);
	if (err)
		goto out;

	dev = to_dev(mr->ibmr.device);
	mutex_lock(&dev->mr_list_mutex);
	list_add_tail(&mr->entry, &dev->mr_list);
	mutex_unlock(&dev->mr_list_mutex);

	return &mr->ibmr;
out:
	ibscif_dereg_mr(ibmr);
	return ERR_PTR(err);
}

void ibscif_complete_mr(struct kref *ref)
{
	struct ibscif_mr *mr = container_of(ref, struct ibscif_mr, ref);
	complete(&mr->done);
}

int ibscif_dereg_mr(struct ib_mr *ibmr)
{
	struct ibscif_dev *dev = to_dev(ibmr->device);
	struct ibscif_mr *mr = to_mr(ibmr);
	struct ibscif_mreg_info *mreg, *next;
	struct ibscif_mr *mr0, *next0;
	int ret;

	ibscif_put_mr(mr);
	wait_for_completion(&mr->done);

	list_for_each_entry_safe(mreg, next, &mr->mreg_list, entry) {
		do {
			ret = scif_unregister(mreg->conn->ep,
					      mreg->aligned_offset,
					      mreg->aligned_length);
		}
		while (ret == -ERESTARTSYS);

		if (ret && ret != -ENOTCONN)
			printk(KERN_ALERT PFX
				"%s: scif_unregister returns %d. ep=%p, "
				"offset=%llx, length=%x\n", __func__, ret,
				mreg->conn->ep, mreg->aligned_offset,
				mreg->aligned_length);

		ibscif_put_conn(mreg->conn);
		list_del(&mreg->entry);
		kfree(mreg);
	}

	mutex_lock(&dev->mr_list_mutex);
	list_for_each_entry_safe(mr0, next0, &dev->mr_list, entry) {
		if (mr0 == mr) {
			list_del(&mr0->entry);
			break;
		}
	}
	mutex_unlock(&dev->mr_list_mutex);

	if (mr->pinned_pages)
		scif_unpin_pages(mr->pinned_pages);

	if (mr->umem && !IS_ERR(mr->umem))
		ib_umem_release(mr->umem);
	if (mr->page)
		vfree(mr->page);

	ibscif_release_quota(mr->npages);
	atomic_dec(&dev->mr_cnt);

	ibscif_wiremap_del(mr->ibmr.lkey);

	kfree(mr);
	return 0;
}

/*
 * Lookup and validate the given memory region access.  A reference is
 * held on success.
 */
struct ibscif_mr *ibscif_validate_mr(u32 key, u64 addr, int length,
				     struct ib_pd *ibpd,
				     enum ib_access_flags access)
{
	struct ibscif_mr *mr;
	int err;

	mr = ibscif_get_mr(key);
	if (unlikely(IS_ERR(mr)))
		return mr;

	if (unlikely(mr->ibmr.pd != ibpd)) {
		err = -EPERM;
		goto out;
	}
	if (unlikely(access && !(mr->access & access))) {
		err = -EACCES;
		goto out;
	}
	if (unlikely((addr < mr->addr) ||
	    ((addr + length) > (mr->addr + mr->length)))) {
		err = -ERANGE;
		goto out;
	}

	return mr;
out:
	ibscif_put_mr(mr);
	return ERR_PTR(err);
}

static void ibscif_dma_nop(struct ib_device *ibdev, u64 addr, size_t size,
			   enum dma_data_direction direction)
{
}

static int ibscif_mapping_error(struct ib_device *ibdev, u64 dma_addr)
{
	return !dma_addr;
}

static u64 ibscif_dma_map_single(struct ib_device *ibdev, void *cpu_addr,
				 size_t size, enum dma_data_direction dir)
{
	return (u64)cpu_addr;
}

static u64 ibscif_dma_map_page(struct ib_device *ibdev, struct page *page,
			       unsigned long offset, size_t size,
			       enum dma_data_direction dir)
{
	u64 addr;

	if (offset + size > PAGE_SIZE)
		return 0;

	addr = (u64)page_address(page);
	if (addr)
		addr += offset;

	return addr;
}

static int ibscif_map_sg(struct ib_device *ibdev, struct scatterlist *sg,
			 int nents, enum dma_data_direction dir)
{
	u64 addr;
	int i, ret = nents;

	for (i = 0; i < nents; i++, sg++) {
		addr = (u64)page_address(sg_page(sg));
		if (!addr) {
			ret = 0;
			break;
		}

		sg->dma_address = sg->offset + addr;
		sg->dma_length  = sg->length;
	}
	return ret;
}

static void ibscif_unmap_sg(struct ib_device *ibdev, struct scatterlist *sg,
			    int nents, enum dma_data_direction dir)
{
}

static void ibscif_sync_single(struct ib_device *ibdev, u64 dma, size_t size,
			       enum dma_data_direction dir)
{
}

static void *ibscif_dma_alloc_coherent(struct ib_device *ibdev, size_t size,
				       u64 *dma_handle, gfp_t flag)
{
	struct page *p = alloc_pages(flag, get_order(size));
	void *addr = p ? page_address(p) : NULL;

	if (dma_handle)
		*dma_handle = (u64)addr;

	return addr;
}

static void ibscif_dma_free_coherent(struct ib_device *ibdev, size_t size,
				     void *cpu_addr, u64 dma_handle)
{
	free_pages((unsigned long)cpu_addr, get_order(size));
}

struct ib_dma_mapping_ops ibscif_dma_mapping_ops = {
	ibscif_mapping_error,
	ibscif_dma_map_single,
	ibscif_dma_nop,
	ibscif_dma_map_page,
	ibscif_dma_nop,
	ibscif_map_sg,
	ibscif_unmap_sg,
	ibscif_sync_single,
	ibscif_sync_single,
	ibscif_dma_alloc_coherent,
	ibscif_dma_free_coherent
};

static void ibscif_dump_mr_list( struct ibscif_dev *dev )
{
	struct ibscif_mr *mr;

	list_for_each_entry(mr, &dev->mr_list, entry){
		printk(KERN_ALERT PFX "%s: mr=%p [%llx, %x, %x]\n",
			__func__, mr, mr->addr, mr->length, mr->ibmr.rkey);
	}
}

static int ibscif_mr_reg_with_conn(struct ibscif_mr *mr,
				   struct ibscif_conn *conn,
				   struct ibscif_mreg_info **new_mreg)
{
	struct ibscif_mreg_info *mreg;
	off_t offset, aligned_offset;
	u64 aligned_addr;
	int aligned_length;
	int offset_in_page;
	int err;

	aligned_addr = mr->addr & PAGE_MASK;
	offset_in_page = (int)(mr->addr & ~PAGE_MASK);
	aligned_length = (mr->length + offset_in_page + PAGE_SIZE - 1) &
			 PAGE_MASK;
	aligned_offset = IBSCIF_MR_VADDR_TO_OFFSET(mr->ibmr.rkey, aligned_addr);

	offset = scif_register_pinned_pages(conn->ep, mr->pinned_pages,
					    aligned_offset, SCIF_MAP_FIXED);

	if (IS_ERR_VALUE(offset)) {
		printk(KERN_ALERT PFX
			"%s: scif_register_pinned_pages returns %d\n",
			__func__, (int)offset);
		printk(KERN_ALERT PFX
			"%s: conn=%p, ep=%p, mr=%p, addr=%llx, length=%x, "
			"rkey=%x, aligned_addr=%llx, aligned_length=%x, "
			"aligned_offset=%llx\n", __func__, conn, conn->ep,
			mr, mr->addr, mr->length, mr->ibmr.rkey, aligned_addr,
			aligned_length, (uint64_t)aligned_offset);
		ibscif_dump_mr_list(conn->dev);
		return (int)offset;
	}

	BUG_ON(offset != aligned_offset);

	offset += offset_in_page;

	mreg = kzalloc(sizeof(struct ibscif_mreg_info), GFP_KERNEL);
	if (!mreg) {
		do {
			err = scif_unregister(conn->ep, aligned_offset,
					      aligned_length);
		}
		while (err == -ERESTARTSYS);

		if (err && err != -ENOTCONN)
			printk(KERN_ALERT PFX
				"%s: scif_unregister returns %d. ep=%p, "
				"offset=%llx, length=%x\n", __func__, err,
				conn->ep, (uint64_t)aligned_offset,
				aligned_length);

		return -ENOMEM;
	}
	mreg->conn = conn;
	mreg->offset = (u64)offset;
	mreg->aligned_offset = aligned_offset;
	mreg->aligned_length = aligned_length;
	list_add_tail(&mreg->entry, &mr->mreg_list);

	atomic_inc(&conn->refcnt);
	if (conn->local_close) {
		conn->local_close = 0;
		ibscif_send_reopen(conn);
	}

	if (new_mreg)
		*new_mreg = mreg;

	return 0;
}

struct ibscif_mreg_info *ibscif_mr_get_mreg(struct ibscif_mr *mr,
					    struct ibscif_conn *conn)
{
	struct ibscif_mreg_info *mreg;
	int err;
	int i;

	if (unlikely(!conn)) {
		printk(KERN_ALERT PFX "%s: conn==NULL\n", __func__);
		return NULL;
	}

	list_for_each_entry(mreg, &mr->mreg_list, entry){
		if (mreg->conn == conn)
			return mreg;
	}

	mreg = NULL;
	err = ibscif_mr_reg_with_conn(mr, conn, &mreg);
	if (err != -EADDRINUSE)
		return mreg;

	/* another thread is performing the registration */
	if (verbose)
		printk(KERN_INFO PFX
			"%s: mr is being registered by another thread. "
			"mr=%p, conn=%p.\n", __func__, mr, conn);
	for (i=0; i<10000; i++) {
		list_for_each_entry(mreg, &mr->mreg_list, entry){
			if (mreg->conn == conn) {
				if (verbose)
					printk(KERN_INFO PFX
						"%s: succ after %d tries.\n",
						__func__, i+1);
				return mreg;
			}
		}
		schedule();
	}
	if (verbose)
		printk(KERN_INFO PFX
			"%s: failed to get mreg after %d tries.\n",
			__func__, i);
	return NULL;
}

static int ibscif_mr_init_mreg(struct ibscif_mr *mr)
{
	struct ibscif_dev *dev = to_dev(mr->ibmr.device);
	struct ibscif_conn *conn;
	int prot;
	u64 aligned_addr;
	int aligned_length;
	int offset_in_page;
	int err;

	aligned_addr = mr->addr & PAGE_MASK;
	offset_in_page = (int)(mr->addr & ~PAGE_MASK);
	aligned_length = (mr->length + offset_in_page + PAGE_SIZE - 1) &
			 PAGE_MASK;

#if 0
	prot =  ((mr->access & IB_ACCESS_REMOTE_READ)? SCIF_PROT_READ : 0) |
		((mr->access & IB_ACCESS_REMOTE_WRITE)? SCIF_PROT_WRITE : 0);
#else
	/* In IB, the same buffer can be registered multiple times with
	 * different access rights. SCIF doesn't have mechanism to support
	 * that. So we just turn on all the access rights. Otherwise we may
	 * end up with protection error.
	 */
	prot = SCIF_PROT_READ | SCIF_PROT_WRITE;
#endif

	err = scif_pin_pages((void *)aligned_addr, aligned_length, prot,
			     0/*user addr*/, &mr->pinned_pages);
	if (err) {
		printk(KERN_ALERT PFX "%s: scif_pin_pages returns %d\n",
			__func__, err);
		return err;
	}

	mutex_lock(&dev->mutex);
	list_for_each_entry(conn, &dev->conn_list, entry) {
		err = ibscif_mr_reg_with_conn(mr, conn, NULL);
		if (err)
			break;
	}
	mutex_unlock(&dev->mutex);

	return err;
}

void ibscif_refresh_mreg( struct ibscif_conn *conn )
{
	struct ibscif_mr *mr;

	mutex_lock(&conn->dev->mr_list_mutex);
	list_for_each_entry(mr, &conn->dev->mr_list, entry){
		ibscif_mr_get_mreg(mr, conn);
	}
	mutex_unlock(&conn->dev->mr_list_mutex);
}

