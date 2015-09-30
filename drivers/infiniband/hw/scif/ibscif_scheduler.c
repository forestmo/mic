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

static int ibscif_schedule_tx(struct ibscif_wq *wq, int max_send)
{
	struct ibscif_tx_state *tx = &wq->wirestate->tx;
	struct ibscif_qp *qp = wq->qp;
	struct ibscif_wr *wr;
	int index, sent = 0;

	while ((wq->next_wr != wq->tail) && ibscif_tx_window(tx) && max_send) {

		index = wq->next_wr;
		wr = ibscif_get_wr(wq, index);

		/*
		 * Ack processing can reschedule a WR that is in retry;
		 * only process it if we are all caught up. Also, do not
		 * start a fenced WR until all prior RDMA read and atomic
		 * operations have completed.
		 */
		if ((wr->flags & IB_SEND_FENCE) && atomic_read(&qp->or_depth) &&
		    (wr->state == WR_WAITING))
			break;

		switch (wr->opcode) {
		case WR_RDMA_READ:
		case WR_ATOMIC_CMP_AND_SWP:
		case WR_ATOMIC_FETCH_AND_ADD:
			/* Throttle IQ stream requests if needed. */
			if (wr->state == WR_WAITING) {
				if (atomic_read(&qp->or_depth) == qp->max_or)
					return 0;
				atomic_inc(&qp->or_depth);
			}
			/* Fall through. */
		case WR_SEND:
		case WR_SEND_WITH_IMM:
		case WR_RDMA_WRITE:
		case WR_RDMA_WRITE_WITH_IMM:
		case WR_RDMA_READ_RSP:
		case WR_ATOMIC_RSP:
		case WR_RMA_RSP:
			sent = ibscif_xmit_wr(wq, wr, min((u32)max_send,
					      ibscif_tx_window(tx)), 0,
					      tx->next_seq, &tx->next_seq);
			break;
		case WR_UD:
			sent = ibscif_xmit_wr(wq, wr, min((u32)max_send,
					      ibscif_tx_window(tx)), 0,
					      0, NULL);
			break;
		default:
			printk(KERN_ERR PFX
				"%s() botch: found opcode %d on work queue\n",
			       __func__, wr->opcode);
			return -EOPNOTSUPP;
		}

		/* If an IQ stream request did not get started we need to
		 * back off or_depth.
		 */
		if ((wr->state == WR_WAITING) &&
		    ((wr->opcode == WR_RDMA_READ) ||
		     (wr->opcode == WR_ATOMIC_CMP_AND_SWP) ||
		     (wr->opcode == WR_ATOMIC_FETCH_AND_ADD)))
			atomic_dec(&qp->or_depth);

		if (sent < 0)
			return sent;

		 max_send -= sent;

		/*
		 * The tx engine bumps next_wr when finished sending a
		 * whole WR.Bail if it didn't this time around.
		 */
		if (wq->next_wr == index)
			break;
	}

	return 0;
}

static int ibscif_schedule_wq(struct ibscif_wq *wq)
{
	int max_send, err = 0;
	int need_call_sq_completions = 0;

	/* Ignore loopback QPs that may be scheduled by retry processing. */
	if (wq->qp->loopback)
		return 0;

	if (!(max_send = atomic_read(&wq->qp->dev->available)))
		return -EBUSY;

	spin_lock(&wq->lock);
	err = ibscif_schedule_tx(wq, max_send);
	need_call_sq_completions = wq->fast_rdma_completions;
	wq->fast_rdma_completions = 0;
	spin_unlock(&wq->lock);

	if (unlikely(err))
		ibscif_qp_internal_disconnect(wq->qp, IBSCIF_REASON_QP_FATAL);

	if (fast_rdma && need_call_sq_completions)
		ibscif_process_sq_completions(wq->qp);

	return err;
}

void ibscif_schedule(struct ibscif_wq *wq)
{
	struct ibscif_dev *dev;
	struct list_head processed;

	if (wq->qp->loopback) {
		ibscif_loopback(wq);
		return;
	}
	dev = wq->qp->dev;

	if (!ibscif_schedule_wq(wq))
		goto out;

	while (atomic_xchg(&dev->was_new, 0)) {
		/* Bail if the device is busy. */
		if (mutex_trylock(&dev->mutex))
			goto out;

		/*
		 * Schedule each WQ on the device and move it to the processed
		 * list. When complete, append the processed list to the
		 * device WQ list.
		 */
		INIT_LIST_HEAD(&processed);
		while (!list_empty(&dev->wq_list)) {
			wq = list_entry(dev->wq_list.next, typeof(*wq), entry);
			if (!ibscif_schedule_wq(wq)) {
				DEV_STAT(dev, sched_exhaust++);
				list_splice(&processed, dev->wq_list.prev);
				mutex_unlock(&dev->mutex);
				goto out;
			}
			list_move_tail(&wq->entry, &processed);
		}
		list_splice(&processed, dev->wq_list.prev);

		mutex_unlock(&dev->mutex);
	}
	return;
out:
	atomic_inc(&dev->was_new);
}

void ibscif_scheduler_add_qp(struct ibscif_qp *qp)
{
	struct ibscif_dev *dev = qp->dev;

	mutex_lock(&dev->mutex);
	list_add_tail(&qp->sq.entry, &dev->wq_list);
	list_add_tail(&qp->iq.entry, &dev->wq_list);
	mutex_unlock(&dev->mutex);
}

void ibscif_scheduler_remove_qp(struct ibscif_qp *qp)
{
	struct ibscif_dev *dev = qp->dev;

	mutex_lock(&dev->mutex);
	list_del(&qp->sq.entry);
	list_del(&qp->iq.entry);
	mutex_unlock(&dev->mutex);
}
