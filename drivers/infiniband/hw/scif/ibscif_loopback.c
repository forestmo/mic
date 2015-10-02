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

struct ibscif_seg {
	enum ib_access_flags	access;
	struct ibscif_ds	*ds;
	struct ibscif_mr	*mr;
	struct page		**page;
	void			*addr;
	u32			offset;
	u32			ds_len;
	u32			pg_len;
	void			*(*map)(struct page *page);
	void			(*unmap)(struct page *page, void *addr);
};

static void ibscif_seg_init(struct ibscif_seg *seg, struct ibscif_ds *ds,
			    void *(*map)(struct page *page),
			    void (*unmap)(struct page *page, void *addr),
			    enum ib_access_flags access)
{
	memset(seg, 0, sizeof *seg);
	seg->ds	    = ds;
	seg->map    = map;
	seg->unmap  = unmap;
	seg->access = access;
}

static void ibscif_seg_fini(struct ibscif_seg *seg)
{
	seg->unmap(*seg->page, seg->addr);
	if (likely(seg->mr))
		ibscif_put_mr(seg->mr);
}

static int ibscif_seg_set(struct ibscif_seg *seg, u32 length, u32 copy_len)
{
	struct page **prev_page;

	if (!seg->ds_len) {

		if (seg->mr)
			ibscif_put_mr(seg->mr);

		seg->mr = ibscif_get_mr(seg->ds->lkey);
		if (unlikely(IS_ERR(seg->mr)))
			return PTR_ERR(seg->mr);

		if (unlikely(seg->access && !(seg->mr->access & seg->access)))
			return -EACCES;

		prev_page    = seg->page;
		seg->offset  = seg->ds->offset + (seg->mr->addr & ~PAGE_MASK);
		seg->page    = &seg->mr->page[seg->offset >> PAGE_SHIFT];
		seg->offset &= ~PAGE_MASK;
		seg->ds_len  = seg->ds->length;
		seg->pg_len  = min(seg->ds_len, (u32)PAGE_SIZE - seg->offset);
		seg->pg_len  = min(seg->pg_len, length);

		if (seg->page != prev_page)
			seg->addr = seg->map(*seg->page) + seg->offset;

		seg->ds++;

	} else if (!seg->pg_len) {

		seg->unmap(*seg->page, seg->addr);

		seg->page++;
		seg->addr   = seg->map(*seg->page);
		seg->pg_len = min(seg->ds_len, (u32)PAGE_SIZE);
		seg->pg_len = min(seg->pg_len, length);
	} else
		seg->addr += copy_len;

	return 0;
}

static inline int ibscif_seg_copy(struct ibscif_seg *dst,
				  struct ibscif_seg *src, u32 length,
				  int head_copied)
{
	src->ds_len -= length;
	src->pg_len -= length;

	dst->ds_len -= length;
	dst->pg_len -= length;

	return ibscif_atomic_copy(dst->addr, src->addr, length, head_copied);
}

/*
 * Copy data from the source to the destination data segment list.
 * This is a bit complicated since we must map and copy each page
 * individually and because each data segment can be split across
 * multiple pages within the memory region as illustrated below:
 *
 *	+---page---+   +---page---+   +---page---+
 *	|  .~~mr~~~|~~~|~~~~~~~~~~|~~~|~~~~~~.   |
 *	|  |       |   |  [==ds===|===|====] |   |
 *	|  '~~~~~~~|~~~|~~~~~~~~~~|~~~|~~~~~~'   |
 *	+----------+   +----------+   +----------+
 *
 * For example, due to different buffer page offsets, copying data
 * between the following buffers will result in five separate copy
 * operations as shown by the numeric labels below:
 *
 *	       +----------+     +----------+
 *	       |          |     |          |
 *	       |1111111111|     |          |
 *	       |2222222222|     |1111111111|
 *	       +----------+     +----------+
 *
 *	       +----------+     +----------+
 *	       |3333333333|     |2222222222|
 *	       |3333333333|     |3333333333|
 *	       |4444444444|     |3333333333|
 *	       +----------+     +----------+
 *
 *	       +----------+     +----------+
 *	       |5555555555|     |4444444444|
 *	       |          |     |5555555555|
 *	       |          |     |          |
 *	       +----------+     +----------+
 *
 * The source and destination data segment list lengths are
 * assumed to have been validated outside of this function.
 */
static int ibscif_dscopy(struct ibscif_ds *dst_ds, struct ibscif_ds *src_ds,
			 u32 length)
{
	struct ibscif_seg src, dst;
	int head_copied;
	u32 copy_len;
	int err = 0;

	ibscif_seg_init(&src, src_ds, ibscif_map_src, ibscif_unmap_src, 0);
	ibscif_seg_init(&dst, dst_ds, ibscif_map_dst, ibscif_unmap_dst,
			IB_ACCESS_LOCAL_WRITE);

	head_copied = 0;
	for (copy_len = 0; length; length -= copy_len) {

		err = ibscif_seg_set(&src, length, copy_len);
		if (unlikely(err))
			break;
		err = ibscif_seg_set(&dst, length, copy_len);
		if (unlikely(err))
			break;

		copy_len = min(src.pg_len, dst.pg_len);
		head_copied = ibscif_seg_copy(&dst, &src, copy_len,
					      head_copied);
	}

	ibscif_seg_fini(&src);
	ibscif_seg_fini(&dst);

	return err;
}

/* Hold sq->lock during this call for synchronization. */
static int ibscif_complete_sq_wr(struct ibscif_wq *sq,
				 struct ibscif_wr *send_wr,
				 enum ib_wc_status status)
{
	struct ibscif_qp *qp = sq->qp;
	struct ibscif_wc *wc;
	int err;

	ibscif_clear_ds_refs(send_wr->ds_list, send_wr->num_ds);
	sq->completions++;
	sq->reap++;

	if (send_wr->flags & IB_SEND_SIGNALED) {
		struct ibscif_cq *cq = to_cq(qp->ibqp.send_cq);

		err = ibscif_reserve_cqe(cq, &wc);
		if (unlikely(err))
			return err;

		wc->ibwc.qp	  = &qp->ibqp;
		wc->ibwc.src_qp	  = qp->remote_qpn;
		wc->ibwc.wr_id	  = send_wr->id;
		wc->ibwc.opcode	  = to_ib_wc_opcode(
					(enum ib_wr_opcode)send_wr->opcode);
		wc->ibwc.status	  = status;
		wc->ibwc.ex.imm_data = 0;
		wc->ibwc.port_num = 1;

		switch ((enum ib_wr_opcode) send_wr->opcode) {
		case IB_WR_RDMA_READ:
			wc->ibwc.byte_len = send_wr->read.remote_length;
			break;
		case IB_WR_ATOMIC_CMP_AND_SWP:
		case IB_WR_ATOMIC_FETCH_AND_ADD:
			 wc->ibwc.byte_len =
				sizeof send_wr->atomic_rsp.orig_data;
			break;
		default:
			wc->ibwc.byte_len = send_wr->length;
			break;
		}

		wc->wq	 = sq;
		wc->reap = sq->reap;
		sq->reap = 0;

		ibscif_append_cqe(cq, wc, 0);
	}

	return 0;
}

/* Hold rq->lock during this call for synchronization. */
static int ibscif_complete_rq_wr(struct ibscif_wq *rq,
				 struct ibscif_wr *recv_wr,
				 struct ibscif_wr *send_wr,
				 enum ib_wc_status status)
{
	struct ibscif_qp *qp = rq->qp;
	struct ibscif_cq *cq = to_cq(qp->ibqp.recv_cq);
	struct ibscif_wc *wc;
	int err;

	ibscif_clear_ds_refs(recv_wr->ds_list, recv_wr->num_ds);

	err = ibscif_reserve_cqe(cq, &wc);
	if (unlikely(err))
		return err;

	wc->ibwc.qp	  = &qp->ibqp;
	wc->ibwc.src_qp	  = qp->remote_qpn;
	wc->ibwc.wr_id	  = recv_wr->id;
	wc->ibwc.status	  = status;
	wc->ibwc.byte_len = send_wr->length;
	wc->ibwc.port_num = 1;

	switch ((enum ib_wr_opcode) send_wr->opcode) {
	case IB_WR_SEND_WITH_IMM:
		DEV_STAT(qp->dev, recv_imm++);
		wc->ibwc.opcode	  = IB_WC_RECV_RDMA_WITH_IMM;
		wc->ibwc.ex.imm_data =
			cpu_to_be32(send_wr->send.immediate_data);
		break;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		DEV_STAT(qp->dev, recv_imm++);
		wc->ibwc.opcode	  = IB_WC_RECV_RDMA_WITH_IMM;
		wc->ibwc.ex.imm_data =
			cpu_to_be32(send_wr->write.immediate_data);
		break;
	default:
		DEV_STAT(qp->dev, recv++);
		wc->ibwc.opcode	  = IB_WC_RECV;
		wc->ibwc.ex.imm_data = 0;
		break;
	}

	wc->wq	 = rq;
	wc->reap = 1;
	rq->completions++;

	ibscif_append_cqe(cq, wc, !!(send_wr->flags & IB_SEND_SOLICITED));

	return 0;
}

/* Hold wq lock during this call for synchronization. */
static int ibscif_validate_wq(struct ibscif_wq *wq, struct ibscif_wr **wr,
			      enum ib_access_flags access)
{
	if (unlikely(wq->qp->state != QP_CONNECTED))
		return -ENOTCONN;

	if (unlikely(access && !(wq->qp->access & access)))
		return -EACCES;

	if (wr) {
		int next;

		if (unlikely(!wq->size))
			return -ENOSPC;

		next = (wq->head + wq->completions) % wq->size;

		if (unlikely(next == wq->tail))
			return -ENOBUFS;

		*wr = ibscif_get_wr(wq, next);
	}

	return 0;
}

static int ibscif_loopback_send(struct ibscif_wq *sq, struct ibscif_wq *rq,
				struct ibscif_wr *send_wr)
{
	struct ibscif_wr *recv_wr;
	int err;

	spin_lock_bh(&rq->lock);

	err = ibscif_validate_wq(rq, &recv_wr, 0);
	if (unlikely(err))
		goto out;

	if (likely(send_wr->length)) {
		if (unlikely(send_wr->length > recv_wr->length)) {
			err = -EMSGSIZE;
			goto out;
		}

		err = ibscif_dscopy(recv_wr->ds_list, send_wr->ds_list,
				    send_wr->length);
		if (unlikely(err))
			goto out;
	}

	err = ibscif_complete_rq_wr(rq, recv_wr, send_wr, IB_WC_SUCCESS);
out:
	spin_unlock_bh(&rq->lock);

	return err;
}

static int ibscif_loopback_write(struct ibscif_wq *sq, struct ibscif_wq *rq,
				 struct ibscif_wr *write_wr)
{
	struct ibscif_wr *recv_wr = NULL;
	struct ibscif_mr *dst_mr = ERR_PTR(-ENOENT);
	int err;

	spin_lock_bh(&rq->lock);

	err = ibscif_validate_wq(rq,
				 ((enum ib_wr_opcode)write_wr->opcode ==
					IB_WR_RDMA_WRITE_WITH_IMM) ?
					&recv_wr : NULL,
				 IB_ACCESS_REMOTE_WRITE);
	if (unlikely(err))
		goto out;

	if (likely(write_wr->length)) {
		struct ibscif_ds dst_ds;

		dst_mr = ibscif_validate_mr(write_wr->write.rkey,
					    write_wr->write.remote_address,
					    write_wr->length, rq->qp->ibqp.pd,
					    IB_ACCESS_REMOTE_WRITE);
		if (unlikely(IS_ERR(dst_mr))) {
			err = PTR_ERR(dst_mr);
			goto out;
		}

		dst_ds.mr     = dst_mr;
		dst_ds.offset = write_wr->write.remote_address - dst_mr->addr;
		dst_ds.length = write_wr->length;
		dst_ds.lkey   = dst_mr->ibmr.lkey;

		err = ibscif_dscopy(&dst_ds, write_wr->ds_list, dst_ds.length);
		if (unlikely(err))
			goto out;
	} else
		err = 0;

	if (recv_wr)
		err = ibscif_complete_rq_wr(rq, recv_wr, write_wr,
					    IB_WC_SUCCESS);
out:
	if (likely(!IS_ERR(dst_mr)))
		ibscif_put_mr(dst_mr);

	spin_unlock_bh(&rq->lock);

	return err;
}

static int ibscif_loopback_read(struct ibscif_wq *sq, struct ibscif_wq *iq,
				struct ibscif_wr *read_wr)
{
	struct ibscif_mr *src_mr = ERR_PTR(-ENOENT);
	int err;

	spin_lock_bh(&iq->lock);

	err = ibscif_validate_wq(iq, NULL, IB_ACCESS_REMOTE_READ);
	if (unlikely(err))
		goto out;

	if (!iq->size) {
		err = -ENOBUFS;
		goto out;
	}

	if (likely(read_wr->read.remote_length)) {
		struct ibscif_ds src_ds;

		src_mr = ibscif_validate_mr(read_wr->read.rkey,
					    read_wr->read.remote_address,
					    read_wr->read.remote_length,
					    iq->qp->ibqp.pd,
					    IB_ACCESS_REMOTE_READ);
		if (unlikely(IS_ERR(src_mr))) {
			err = PTR_ERR(src_mr);
			goto out;
		}

		src_ds.mr     = src_mr;
		src_ds.offset = read_wr->read.remote_address - src_mr->addr;
		src_ds.length = read_wr->read.remote_length;
		src_ds.lkey   = src_mr->ibmr.lkey;

		err = ibscif_dscopy(read_wr->ds_list, &src_ds, src_ds.length);
	} else
		err = 0;
out:
	if (likely(!IS_ERR(src_mr)))
		ibscif_put_mr(src_mr);

	spin_unlock_bh(&iq->lock);

	atomic_dec(&sq->qp->or_posted);

	return err;
}

static int ibscif_loopback_atomic(struct ibscif_wq *sq, struct ibscif_wq *iq,
				  struct ibscif_wr *atomic_wr)
{
	struct ibscif_mr *src_mr = ERR_PTR(-ENOENT);
	struct ibscif_ds  src_ds;
	struct page *src_page;
	u64 *src_addr, addr;
	u32 src_offset, rkey;
	int err;

	if ((enum ib_wr_opcode)atomic_wr->opcode == IB_WR_ATOMIC_CMP_AND_SWP) {
		addr = atomic_wr->cmp_swp.remote_address;
		rkey = atomic_wr->cmp_swp.rkey;
	} else {
		addr = atomic_wr->fetch_add.remote_address;
		rkey = atomic_wr->fetch_add.rkey;
	}

	spin_lock_bh(&iq->lock);

	err = ibscif_validate_wq(iq, NULL, IB_ACCESS_REMOTE_ATOMIC);
	if (unlikely(err))
		goto out;

	if (!iq->size) {
		err = -ENOBUFS;
		goto out;
	}

	src_mr = ibscif_validate_mr(rkey, addr,
				    sizeof atomic_wr->atomic_rsp.orig_data,
				    iq->qp->ibqp.pd, IB_ACCESS_REMOTE_ATOMIC);
	if (unlikely(IS_ERR(src_mr))) {
		err = PTR_ERR(src_mr);
		goto out;
	}

	/* Build a source data segment to copy the original data. */
	src_ds.mr     = src_mr;
	src_ds.offset = addr - src_mr->addr;
	src_ds.length = sizeof atomic_wr->atomic_rsp.orig_data;
	src_ds.lkey   = src_mr->ibmr.lkey;

	/* Determine which page to map. */
	src_offset  = src_ds.offset + (src_mr->addr & ~PAGE_MASK);
	src_page    = src_mr->page[src_offset >> PAGE_SHIFT];
	src_offset &= ~PAGE_MASK;

	/* Lock to perform the atomic operation atomically. */
	spin_lock_bh(&iq->qp->dev->atomic_op);

	/* Copy the original data; this handles any ds_list crossing. */
	err = ibscif_dscopy(atomic_wr->ds_list, &src_ds,
			    sizeof atomic_wr->atomic_rsp.orig_data);
	if (likely(!err)) {
		src_addr = ibscif_map_src(src_page) + src_offset;
		if ((enum ib_wr_opcode)atomic_wr->opcode ==
		    IB_WR_ATOMIC_FETCH_AND_ADD)
			 *src_addr += atomic_wr->fetch_add.add_operand;
		else if (*src_addr == atomic_wr->cmp_swp.cmp_operand)
			 *src_addr  = atomic_wr->cmp_swp.swp_operand;
		ibscif_unmap_src(src_page, src_addr);
	}

	/* Atomic operation is complete. */
	spin_unlock_bh(&iq->qp->dev->atomic_op);
out:
	if (likely(!IS_ERR(src_mr)))
		ibscif_put_mr(src_mr);

	spin_unlock_bh(&iq->lock);

	atomic_dec(&sq->qp->or_posted);

	return err;
}

void ibscif_loopback_disconnect(struct ibscif_qp *qp, enum ibscif_reason reason)
{
	struct ibscif_qp *remote_qp;

	remote_qp = ibscif_get_qp(qp->remote_qpn);
	if (unlikely(IS_ERR(remote_qp)))
		return;

	/* Don't bother if the SQ is connected to the RQ on the same QP. */
	if (remote_qp != qp)
		ibscif_qp_remote_disconnect(remote_qp, reason);

	ibscif_put_qp(remote_qp);
}

/*
 * Loopback QPs connected through the same MAC address.
 * This includes an SQ connected to the RQ on the same QP.
 */
void ibscif_loopback(struct ibscif_wq *sq)
{
	struct ibscif_wq *rq, *iq;
	struct ibscif_qp *remote_qp;
	struct ibscif_wr *wr;
	int status = 0, err = 0;

	BUG_ON(!is_sq(sq));

again:
	remote_qp = ibscif_get_qp(sq->qp->remote_qpn);
	if (unlikely(IS_ERR(remote_qp))) {
		ibscif_qp_remote_disconnect(sq->qp, IBSCIF_REASON_INVALID_QP);
		return;
	}
	rq = &remote_qp->rq;
	iq = &remote_qp->iq;

	DEV_STAT(sq->qp->dev, loopback++);

	spin_lock_bh(&sq->lock);
	for (wr = ibscif_get_wr(sq, sq->next_wr);
	     (sq->next_wr != sq->tail) && !err;
	     sq->next_wr = (sq->next_wr + 1) % sq->size) {

		switch (wr->opcode) {

		case WR_SEND:
		case WR_SEND_WITH_IMM:
			status = ibscif_loopback_send(sq, rq, wr);
			break;
		case WR_RDMA_WRITE:
		case WR_RDMA_WRITE_WITH_IMM:
			status = ibscif_loopback_write(sq, rq, wr);
			break;
		case WR_RDMA_READ:
			status = ibscif_loopback_read(sq, iq, wr);
			break;
		case WR_ATOMIC_CMP_AND_SWP:
		case WR_ATOMIC_FETCH_AND_ADD:
			status = ibscif_loopback_atomic(sq, iq, wr);
			break;
		default:
			status = -ENOSYS;
			break;
		}

		if (likely(!status)) {
			err = ibscif_complete_sq_wr(sq, wr, IB_WC_SUCCESS);

			spin_unlock_bh(&sq->lock);
			ibscif_notify_cq(to_cq(sq->qp->ibqp.send_cq));
			ibscif_notify_cq(to_cq(remote_qp->ibqp.recv_cq));
			spin_lock_bh(&sq->lock);
		} else
			break;
	}
	spin_unlock_bh(&sq->lock);

	if (unlikely(status) && status != -ENOBUFS)
		ibscif_qp_remote_disconnect(sq->qp, IBSCIF_REASON_QP_FATAL);
	else if (unlikely(err))
		ibscif_qp_internal_disconnect(sq->qp, IBSCIF_REASON_QP_FATAL);

	ibscif_put_qp(remote_qp);

	if (status == -ENOBUFS) {
		schedule();
		goto again;
	}
}
