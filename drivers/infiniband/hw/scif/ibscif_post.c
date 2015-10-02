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

/*
 * Build and validate the wr->ds_list from the given sg_list.
 * If successful, a reference is held on each mr in the wr->ds_list.
 */
static int ibscif_wr_ds(struct ib_pd *ibpd, struct ib_sge *sg_list,
			int num_sge, struct ibscif_wr *wr,
			int *total_length, enum ib_access_flags access)
{
	struct ibscif_ds *ds_list = wr->ds_list;
	int err;

	*total_length = 0;
	for (wr->num_ds = 0; wr->num_ds < num_sge; sg_list++, ds_list++) {

		ds_list->mr = ibscif_validate_mr(sg_list->lkey, sg_list->addr,
						 sg_list->length, ibpd, access);
		if (unlikely(IS_ERR(ds_list->mr))) {
			err = PTR_ERR(ds_list->mr);
			goto out;
		}

		ds_list->in_use = 1;
		wr->num_ds++;

		if (unlikely((*total_length + sg_list->length) < *total_length)) {
			err = -EOVERFLOW;
			goto out;
		}

		ds_list->offset = sg_list->addr - ds_list->mr->addr;
		ds_list->length = sg_list->length;
		ds_list->lkey   = sg_list->lkey;
		ds_list->current_mreg = NULL;

		*total_length += ds_list->length;
	}

	return 0;
out:
	ibscif_clear_ds_refs(wr->ds_list, wr->num_ds);
	return err;
}

int ibscif_post_send(struct ib_qp *ibqp, struct ib_send_wr *ibwr,
		     struct ib_send_wr **bad_wr)
{
	struct ibscif_qp *qp = to_qp(ibqp);
	struct ibscif_wq *sq = &qp->sq;
	struct ibscif_wr *wr;
	int nreq = 0, err;

	IBSCIF_PERF_SAMPLE(0, 0);

	spin_lock_bh(&sq->lock);

	if (unlikely(ibqp->qp_type != IB_QPT_UD && qp->state != QP_CONNECTED)) {
		err = -ENOTCONN;
		goto out;
	}
	if (unlikely(!sq->size)) {
		err = -ENOSPC;
		goto out;
	}

	for (err = 0; ibwr; ibwr = ibwr->next, nreq++) {

		if (unlikely(sq->depth == sq->size)) {
			err = -ENOBUFS;
			goto out;
		}
		if (unlikely(ibwr->num_sge > sq->max_sge)) {
			err = -E2BIG;
			goto out;
		}

		wr = ibscif_get_wr(sq, sq->tail);

		memset(&wr->sar, 0, sizeof wr->sar);

		wr->id	   = ibwr->wr_id;
		wr->opcode = ibwr->opcode;
		wr->flags  = ibwr->send_flags |
			     ((qp->sq_policy == IB_SIGNAL_ALL_WR) ?
					IB_SEND_SIGNALED : 0);
		wr->state  = WR_WAITING;
		wr->use_rma = 0;
		wr->rma_id = 0;

		if (ibqp->qp_type == IB_QPT_UD) {
			u16 lid;
			wr->opcode = WR_UD;
			lid = be16_to_cpu(to_ah(ibwr->wr.ud.ah)->dlid);
			wr->ud.remote_node_id = IBSCIF_LID_TO_NODE_ID(lid);
			wr->ud.remote_qpn = ibwr->wr.ud.remote_qpn;

			/* the remainings are the same as IB_WR_SEND */
			err = ibscif_wr_ds(ibqp->pd, ibwr->sg_list,
					   ibwr->num_sge, wr, &wr->length, 0);
			if (unlikely(err))
				goto out;
			wr->msg_id = sq->wirestate->tx.next_msg_id++;
		}

		else switch (ibwr->opcode) {

		case IB_WR_SEND_WITH_IMM:
			wr->send.immediate_data = ibwr->ex.imm_data;
			/* fall through */
		case IB_WR_SEND:
			err = ibscif_wr_ds(ibqp->pd, ibwr->sg_list,
					   ibwr->num_sge, wr, &wr->length, 0);
			if (unlikely(err))
				goto out;
			wr->msg_id = sq->wirestate->tx.next_msg_id++;
			if (wr->length > rma_threshold) {
				wr->use_rma = 1;
				wr->rma_id = sq->next_msg_id;
			}
			break;

		case IB_WR_RDMA_WRITE_WITH_IMM:
			wr->msg_id = sq->wirestate->tx.next_msg_id++;
			wr->write.immediate_data = ibwr->ex.imm_data;
			/* fall through */
		case IB_WR_RDMA_WRITE:
			err = ibscif_wr_ds(ibqp->pd, ibwr->sg_list,
					   ibwr->num_sge, wr, &wr->length, 0);
			if (unlikely(err))
				goto out;
			if (wr->length &&
			    ((ibwr->wr.rdma.remote_addr + wr->length - 1) <
				ibwr->wr.rdma.remote_addr)) {
				err = -EOVERFLOW;
				goto out;
			}
			wr->write.remote_address = ibwr->wr.rdma.remote_addr;
			wr->write.rkey		 = ibwr->wr.rdma.rkey;
			if (ibwr->opcode == IB_WR_RDMA_WRITE)
				wr->msg_id = 0;
			if (wr->length > rma_threshold) {
				wr->use_rma = 1;
				wr->rma_id = sq->next_msg_id;
			}
			break;

		case IB_WR_RDMA_READ:
			if (unlikely(!qp->max_or)) {
				err = -ENOBUFS;
				goto out;
			}
			err = ibscif_wr_ds(ibqp->pd, ibwr->sg_list,
					   ibwr->num_sge, wr, &wr->length,
					   IB_ACCESS_LOCAL_WRITE);
			if (unlikely(err))
				goto out;
			if (wr->length &&
			    ((ibwr->wr.rdma.remote_addr + wr->length - 1) <
				ibwr->wr.rdma.remote_addr)) {
				err = -EOVERFLOW;
				goto out;
			}
			wr->read.remote_address = ibwr->wr.rdma.remote_addr;
			wr->read.remote_length	= wr->length;
			wr->read.rkey		= ibwr->wr.rdma.rkey;
			wr->length		= 0;
			wr->msg_id		= sq->next_msg_id;
			atomic_inc(&qp->or_posted);
			if (wr->read.remote_length > rma_threshold) {
				wr->use_rma = 1;
				wr->rma_id = wr->msg_id;
			}
			break;

		case IB_WR_ATOMIC_CMP_AND_SWP:
		case IB_WR_ATOMIC_FETCH_AND_ADD:
			if (unlikely(!qp->max_or)) {
				err = -ENOBUFS;
				goto out;
			}
			if (unlikely(ibwr->wr.atomic.remote_addr &
				(sizeof wr->atomic_rsp.orig_data - 1))) {
				err = -EADDRNOTAVAIL;
				goto out;
			}
			err = ibscif_wr_ds(ibqp->pd, ibwr->sg_list,
					   ibwr->num_sge, wr, &wr->length,
					   IB_ACCESS_LOCAL_WRITE);
			if (unlikely(err))
				goto out;
			if (unlikely(wr->length <
				sizeof wr->atomic_rsp.orig_data)) {
				err = -EINVAL;
				goto out;
			}
			if (ibwr->opcode == IB_WR_ATOMIC_CMP_AND_SWP) {
				wr->cmp_swp.cmp_operand =
					ibwr->wr.atomic.compare_add;
				wr->cmp_swp.swp_operand =
					ibwr->wr.atomic.swap;
				wr->cmp_swp.remote_address =
					ibwr->wr.atomic.remote_addr;
				wr->cmp_swp.rkey = ibwr->wr.atomic.rkey;
			} else {
				wr->fetch_add.add_operand =
					ibwr->wr.atomic.compare_add;
				wr->fetch_add.remote_address =
					ibwr->wr.atomic.remote_addr;
				wr->fetch_add.rkey = ibwr->wr.atomic.rkey;
			}
			wr->length = 0;
			wr->msg_id = sq->next_msg_id;
			atomic_inc(&qp->or_posted);
			break;

		default:
			err = -ENOMSG;
			goto out;
		}

		DEV_STAT(qp->dev, wr_opcode[wr->opcode]++);
		ibscif_append_wq(sq);
	}
out:
	spin_unlock_bh(&sq->lock);

	IBSCIF_PERF_SAMPLE(1, 0);

	if (err)
		*bad_wr = ibwr;
	if (nreq)
		ibscif_schedule(sq);

	IBSCIF_PERF_SAMPLE(9, 1);

	return err;
}

int ibscif_post_receive(struct ib_qp *ibqp, struct ib_recv_wr *ibwr,
			struct ib_recv_wr **bad_wr)
{
	struct ibscif_qp *qp = to_qp(ibqp);
	struct ibscif_wq *rq = &qp->rq;
	struct ibscif_wr *wr;
	int err;

	spin_lock_bh(&rq->lock);

	if ((qp->state != QP_IDLE) && (qp->state != QP_CONNECTED)) {
		err = -ENOTCONN;
		goto out;
	}
	if (unlikely(!rq->size)) {
		err = -ENOSPC;
		goto out;
	}

	for (err = 0; ibwr; ibwr = ibwr->next) {

		if (unlikely(rq->depth == rq->size)) {
			err = -ENOBUFS;
			goto out;
		}
		if (unlikely(ibwr->num_sge > rq->max_sge)) {
			err = -E2BIG;
			goto out;
		}

		wr = ibscif_get_wr(rq, rq->tail);

		memset(&wr->sar, 0, sizeof wr->sar);

		wr->id	   = ibwr->wr_id;
		wr->msg_id = rq->next_msg_id;
		wr->state  = WR_WAITING;

		err = ibscif_wr_ds(ibqp->pd, ibwr->sg_list, ibwr->num_sge, wr,
				   &wr->length, IB_ACCESS_LOCAL_WRITE);
		ibscif_clear_ds_refs(wr->ds_list, wr->num_ds);
		if (unlikely(err))
			goto out;

		ibscif_append_wq(rq);
	}
out:
	spin_unlock_bh(&rq->lock);
	if (err)
		*bad_wr = ibwr;

	return err;
}
