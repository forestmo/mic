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

static const char ibscif_signon[] = DRV_SIGNON DRV_BUILD;

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION(DRV_DESC);
MODULE_VERSION(DRV_VERSION);

#define MODULE_PARAM(type, name, value, desc)			\
	type name = value;					\
	module_param(name, type, 0664);				\
	MODULE_PARM_DESC(name, desc)

#define MODULE_ARRAY(name, size, value, desc)			\
	unsigned int name##_argc;				\
	char *name[size] = { [0 ... size-1] = value };		\
	module_param_array(name, charp, &name##_argc, 0644);	\
	MODULE_PARM_DESC(name, desc)

#define DEFAULT_MAX_PINNED	50
MODULE_PARAM(int, max_pinned, DEFAULT_MAX_PINNED,
	     "Maximum percent of physical memory that may be pinned");

#define DEFAULT_WINDOW_SIZE	40
MODULE_PARAM(int, window_size, DEFAULT_WINDOW_SIZE,
	     "Maximum number of outstanding unacknowledged packets");

#define DEFAULT_RMA_THRESHOLD	1024
MODULE_PARAM(int, rma_threshold, DEFAULT_RMA_THRESHOLD,
	     "Maximum message size sent through scif_send()");

MODULE_PARAM(int, fast_rdma, 1,
	     "Use scif_writeto/scif_readfrom directly for RDMA write/read");

MODULE_PARAM(int, blocking_send, 0,
	     "Use blocking version of scif_send()");

MODULE_PARAM(int, blocking_recv, 1,
	     "Use blocking version of scif_recv()");

MODULE_PARAM(int, scif_loopback, 1,
	     "Use SCIF lookback instead of kernel copy based loopback");

MODULE_PARAM(int, host_proxy, 0,
	     "Proxy card side RDMA operations to host");

MODULE_PARAM(int, new_ib_type, 1,
	     "Use new transport type dedicated to IBSCIF");

MODULE_PARAM(int, verbose, 0,
	     "Produce more log info for debugging purpose");

MODULE_PARAM(int, check_grh, 1,
	     "Detect outside-box connection by checking the GRH");

static atomic_t avail_pages;

LIST_HEAD(devlist);
DEFINE_MUTEX(devlist_mutex);

DEFINE_IDR(wiremap);
DEFINE_RWLOCK(wiremap_lock);
static u32 reserved_0 = 0;

void ibscif_dump(char *str, unsigned char* buf, int len)
{
	unsigned char *p, tmp[(16*3)+1];
	int i;
	return;
	len = len > 64 ? 64 : len;
	while (len) {
		p = tmp;
		for (i = len > 16 ? 16 : len; i; i--, len--)
			p += sprintf(p, "%2x ", *buf++);
		printk("(%d)%s: %s\n", smp_processor_id(), str, tmp);
	}
}

int ibscif_reserve_quota(int *npages)
{
	int c, old, err;

	if (!*npages)
		return 0;

	err = 0;
	c = atomic_read(&avail_pages);
	for (;;) {
		if (unlikely(c < *npages))
			break;
		old = atomic_cmpxchg(&avail_pages, c, c - *npages);
		if (likely(old == c))
			break;
		c = old;
	}

	if (c < *npages) {
		*npages = 0;
		err = -EDQUOT;
	}

	return err;
}

void ibscif_release_quota(int npages)
{
	if (npages)
		atomic_add(npages, &avail_pages);
}

/*
 * To work around MPI's assumptions that data is written atomically in their
 * header structures, write the first 16 integers of a transfer atomically.
 *
 * Update: the assumption of MPI's ofa module is different in that the last
 * four bytes needs to be written last and atomically. The buffers used in
 * this case is always aligned.
 */
int ibscif_atomic_copy(void *dst_addr, void *src_addr, u32 copy_len,
		       int head_copied)
{
	volatile int *src_x = (int *)src_addr;
	volatile int *dst_x = (int *)dst_addr;
	volatile u8  *src_c, *dst_c;
	int head_aligned, tail_aligned;

	if (unlikely(!copy_len))
		return head_copied;

	head_aligned =	!((unsigned long)src_addr & (sizeof(int)-1)) &&
			!((unsigned long)dst_addr & (sizeof(int)-1));


	tail_aligned =	!((unsigned long)(src_addr+copy_len) & (sizeof(int)-1)) &&
			!((unsigned long)(dst_addr+copy_len) & (sizeof(int)-1));

	if (!head_copied && head_aligned) {

		switch (copy_len) {
		case sizeof(int):
			*dst_x = *src_x;
			goto done;
		case sizeof(int)*2:
			*dst_x++ = *src_x++;
			*dst_x	 = *src_x;
			goto done;
		case sizeof(int)*3:
			*dst_x++ = *src_x++;
			*dst_x++ = *src_x++;
			*dst_x	 = *src_x;
			goto done;
		default:
			if (copy_len >= (sizeof(int)*4)) {
				/* We have at least a whole header to copy. */
				head_copied = 1;
				copy_len -= sizeof(int)*4;

				*dst_x++ = *src_x++;
				*dst_x++ = *src_x++;
				*dst_x++ = *src_x++;

				if (copy_len == 0) {
					*dst_x = *src_x;
					goto done;
				}
				*dst_x++ = *src_x++;
			}
			break;
		}
	}

        /* The last integer is aligned. Copy the last int last. */
        if (tail_aligned && copy_len >= sizeof(int)) {
                copy_len -= sizeof(int);
                if (copy_len)
                        memcpy((void *)dst_x, (void *)src_x, copy_len);
                smp_wmb();
                src_x = (volatile int *)((char *)src_x + copy_len);
                dst_x = (volatile int *)((char *)dst_x + copy_len);
                *dst_x = *src_x;
                goto done;
        }

	/* Bad alignment. Copy all but the last byte, then the last byte */
	if (--copy_len)
		memcpy((void *)dst_x, (void *)src_x, copy_len);

	src_c = ((volatile u8 *)src_x) + copy_len;
	dst_c = ((volatile u8 *)dst_x) + copy_len;
	smp_wmb();
	*dst_c = *src_c;
done:
	return head_copied;
}

int ibscif_wiremap_add(void *obj, int *id)
{
	int ret;

	write_lock_bh(&wiremap_lock);
	ret = idr_alloc(&wiremap, obj, 0, 0, GFP_ATOMIC);
	write_unlock_bh(&wiremap_lock);

	if (ret < 0)
		return ret;

	*id = ret;
	return 0;
}

void ibscif_wiremap_del(int id)
{
	write_lock_bh(&wiremap_lock);
	idr_remove(&wiremap, id);
	write_unlock_bh(&wiremap_lock);
}

static int ibscif_init_wiremap(void)
{
	/*
	 * Instead of treating them as opaque, some applications assert
	 * that returned key values are non-zero.  As a work-around,
	 * reserve the first key from the wiremap.
	 */
	int ret = idr_alloc(&wiremap, &reserved_0, 0, 1, GFP_KERNEL);
	BUG_ON(reserved_0 != 0);
	return ret;
}

static void ibscif_free_wiremap(void)
{
	idr_destroy(&wiremap);
}

static void ibscif_init_params(void)
{
	if ((max_pinned <= 0) || (max_pinned > 100)) {
		max_pinned = DEFAULT_MAX_PINNED;
		printk(KERN_WARNING PFX
			"Corrected max_pinned module parameter to %d.\n",
			max_pinned);
	}
	if (window_size < MIN_WINDOW_SIZE) {
		window_size = MIN_WINDOW_SIZE;
		printk(KERN_WARNING PFX
			"Corrected window_size module parameter to %d.\n",
			window_size);
	}
	if (rma_threshold < 0) {
		rma_threshold = 0x7FFFFFFF;
		printk(KERN_WARNING PFX
			"Corrected rma_threshold module parameter to %d.\n",
			rma_threshold);
	}

	/*
	 * Hardware RDMA devices have built-in limits on the number of
	 * registered pages. The avail_pages variable provides a limit
	 * for this software device.
	 */
	atomic_set(&avail_pages, max_pinned * (totalram_pages / 100));
}

static int __init ibscif_init(void)
{
	int err;

	printk(KERN_INFO PFX "%s\n", ibscif_signon);
	printk(KERN_INFO PFX "max_pinned=%d, window_size=%d, "
			"blocking_send=%d, blocking_recv=%d, "
			"fast_rdma=%d, host_proxy=%d, "
			"rma_threshold=%d, scif_loopback=%d, "
			"new_ib_type=%d, verbose=%d, check_grh=%d\n",
			max_pinned, window_size,
			blocking_send, blocking_recv,
			fast_rdma, host_proxy,
			rma_threshold, scif_loopback,
			new_ib_type, verbose, check_grh);

	ibscif_init_params();

	err = ibscif_init_wiremap();
	if (err)
		return err;

	err = ibscif_dev_init();
	if (!err)
		return 0;

	ibscif_free_wiremap();
	return err;
}

static void __exit ibscif_exit(void)
{
	ibscif_dev_cleanup();
	ibscif_free_wiremap();
	printk(KERN_INFO PFX "unloaded\n");
}

module_init(ibscif_init);
module_exit(ibscif_exit);
