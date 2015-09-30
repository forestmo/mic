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

static void ibscif_cq_tasklet(unsigned long cq_ptr)
{
	struct ibscif_cq *cq = (struct ibscif_cq *)cq_ptr;
	cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
}

struct ib_cq *ibscif_create_cq(struct ib_device *ibdev,
			       const struct ib_cq_init_attr *attr,
			       struct ib_ucontext *context,
			       struct ib_udata *udata)
{
	struct ibscif_dev *dev = to_dev(ibdev);
	struct ibscif_cq *cq;
	int nbytes, npages;
	int entries = attr->cqe;
	int err;

	if (entries < 1 || entries > MAX_CQ_SIZE)
		return ERR_PTR(-EINVAL);

	if (!atomic_add_unless(&dev->cq_cnt, 1, MAX_CQS))
		return ERR_PTR(-EAGAIN);

	cq = kzalloc(sizeof *cq, GFP_KERNEL);
	if (!cq) {
		atomic_dec(&dev->cq_cnt);
		return ERR_PTR(-ENOMEM);
	}

	spin_lock_init(&cq->lock);
	tasklet_init(&cq->tasklet, ibscif_cq_tasklet, (unsigned long)cq);
	cq->state = CQ_READY;

	nbytes = PAGE_ALIGN(entries * sizeof *cq->wc);
	npages = nbytes >> PAGE_SHIFT;

	err = ibscif_reserve_quota(&npages);
	if (err)
		goto out;

	cq->wc = vzalloc(nbytes);
	if (!cq->wc) {
		err = -ENOMEM;
		goto out;
	}

	cq->ibcq.cqe = nbytes / sizeof *cq->wc;

	return &cq->ibcq;
out:
	ibscif_destroy_cq(&cq->ibcq);
	return ERR_PTR(err);
}

int ibscif_resize_cq(struct ib_cq *ibcq, int cqe, struct ib_udata *udata)
{
	struct ibscif_cq *cq = to_cq(ibcq);
	struct ibscif_wc *old_wc, *new_wc;
	int nbytes, old_npages, new_npages, i, err;

	if (cqe < 1 || cqe > MAX_CQ_SIZE)
		return -EINVAL;

	nbytes = PAGE_ALIGN(cqe * sizeof *cq->wc);
	new_npages = nbytes >> PAGE_SHIFT;
	old_npages = PAGE_ALIGN(ibcq->cqe * sizeof *cq->wc) >> PAGE_SHIFT;
	new_npages -= old_npages;

	if (new_npages == 0)
		return 0;

	if (new_npages > 0) {
		err = ibscif_reserve_quota(&new_npages);
		if (err)
			return err;
	}

	new_wc = vzalloc(nbytes);
	if (!new_wc) {
		err = -ENOMEM;
		goto out1;
	}
	cqe = nbytes / sizeof *cq->wc;
	old_wc = cq->wc;

	spin_lock_bh(&cq->lock);

	if (cqe < cq->depth) {
		err = -EBUSY;
		goto out2;
	}

	for (i = 0; i < cq->depth; i++) {
		new_wc[i] = old_wc[cq->head];
		cq->head = (cq->head + 1) % ibcq->cqe;
	}

	cq->wc	  = new_wc;
	cq->head  = 0;
	cq->tail  = cq->depth;
	ibcq->cqe = cqe;

	spin_unlock_bh(&cq->lock);

	if (old_wc)
		vfree(old_wc);
	if (new_npages < 0)
		ibscif_release_quota(-new_npages);

	return 0;
out2:
	spin_unlock_bh(&cq->lock);
	vfree(new_wc);
out1:
	if (new_npages > 0)
		ibscif_release_quota(new_npages);
	return err;
}

int ibscif_destroy_cq(struct ib_cq *ibcq)
{
	struct ibscif_dev *dev = to_dev(ibcq->device);
	struct ibscif_cq *cq = to_cq(ibcq);

	tasklet_kill(&cq->tasklet);

	if (cq->wc)
		vfree(cq->wc);

	ibscif_release_quota(
		PAGE_ALIGN(ibcq->cqe * sizeof *cq->wc) >> PAGE_SHIFT);

	atomic_dec(&dev->cq_cnt);

	kfree(cq);
	return 0;
}

int ibscif_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *entry)
{
	struct ibscif_cq *cq = to_cq(ibcq);
	struct ibscif_wq *wq;
	int i, reap;

	/*
	 * The protocol layer holds WQ lock while processing a packet and
	 * acquires the CQ lock to append a work completion.  To avoid a
	 * deadly embrace, do not hold the CQ lock when adjusting the WQ
	 * reap count.
	 */
	for (i = 0; (i < num_entries) && cq->depth; i++) {

		spin_lock_bh(&cq->lock);
		entry[i] = cq->wc[cq->head].ibwc;
		reap = cq->wc[cq->head].reap;
		cq->depth--;
		wq = cq->wc[cq->head].wq;
		cq->head = (cq->head + 1) % ibcq->cqe;
		spin_unlock_bh(&cq->lock);

		/* WQ may no longer exist or has been flushed. */
		if (wq) {
			spin_lock_bh(&wq->lock);
			wq->head = (wq->head + reap) % wq->size;
			wq->depth -= reap;
			wq->completions -= reap;
			spin_unlock_bh(&wq->lock);
		}
	}

	return i;
}

int ibscif_arm_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags notify)
{
	struct ibscif_cq *cq = to_cq(ibcq);
	int ret;

	spin_lock_bh(&cq->lock);

	cq->arm |= notify & IB_CQ_SOLICITED_MASK;

	if (notify & IB_CQ_SOLICITED)
		cq->solicited = 0;

	ret = (notify & IB_CQ_REPORT_MISSED_EVENTS) && cq->depth;

	spin_unlock_bh(&cq->lock);

	return ret;
}

void ibscif_notify_cq(struct ibscif_cq *cq)
{
	if (!cq->arm || !cq->depth)
		return;

	spin_lock_bh(&cq->lock);
	if ((cq->arm & IB_CQ_NEXT_COMP) ||
	    ((cq->arm & IB_CQ_SOLICITED) && cq->solicited)) {
		cq->arm = 0;
		spin_unlock_bh(&cq->lock);
		tasklet_hi_schedule(&cq->tasklet);
	} else
		spin_unlock_bh(&cq->lock);
}

void ibscif_clear_cqes(struct ibscif_cq *cq, struct ibscif_wq *wq)
{
	struct ibscif_wc *wc;
	int i, j;

	if (!cq)
		return;

	/*
	 * Walk the CQ work completions and clear pointers to the
	 * given WQ to prevent retiring WQEs when CQEs are polled.
	 */
	spin_lock_bh(&cq->lock);
	j = cq->head;
	for (i = 0; i < cq->depth; i++) {
		wc = &cq->wc[j];
		if (wc->wq == wq)
			wc->wq = NULL;
		j = (j + 1) % cq->ibcq.cqe;
	}
	spin_unlock_bh(&cq->lock);
}

/*
 * Acquire lock and reserve a completion queue entry.
 * Note that cq->lock is held upon successful completion of this call.
 * On error, WQs affiliated with this CQ should generate an event and
 * transition to the error state; refer to IB Spec r1.2 C11-39 and C11-40.
 */
int ibscif_reserve_cqe(struct ibscif_cq *cq, struct ibscif_wc **wc)
{
	spin_lock_bh(&cq->lock);

	if (cq->state != CQ_READY) {
		spin_unlock_bh(&cq->lock);
		return -EIO;
	}
	if (!cq->ibcq.cqe) {
		spin_unlock_bh(&cq->lock);
		return -ENOSPC;
	}
	if (cq->depth == cq->ibcq.cqe) {
		cq->state = CQ_ERROR;
		spin_unlock_bh(&cq->lock);

		if (cq->ibcq.event_handler) {
			struct ib_event record;
			record.event	  = IB_EVENT_CQ_ERR;
			record.device	  = cq->ibcq.device;
			record.element.cq = &cq->ibcq;
			cq->ibcq.event_handler(&record, cq->ibcq.cq_context);
		}
		return -ENOBUFS;
	}

	*wc = &cq->wc[cq->tail];

	return 0;
}

/*
 * Append a completion queue entry and release lock.
 * Note that this function assumes that the cq->lock is currently held.
 */
void ibscif_append_cqe(struct ibscif_cq *cq, struct ibscif_wc *wc,
		       int solicited)
{
	cq->solicited = !!(solicited || (wc->ibwc.status != IB_WC_SUCCESS));
	cq->tail = (cq->tail + 1) % cq->ibcq.cqe;
	cq->depth++;

	spin_unlock_bh(&cq->lock);
}
