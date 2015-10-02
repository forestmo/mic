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

#ifndef IBSCIF_DRIVER_H
#define IBSCIF_DRIVER_H

#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/idr.h>
#include <linux/if_arp.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/pkt_sched.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/scif.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/iw_cm.h>
#include "ibscif_protocol.h"

/* SCIF ports reserved for OFED */
#ifndef SCIF_OFED_PORT_0
#define SCIF_OFED_PORT_0	60
#define SCIF_OFED_PORT_1	61
#define SCIF_OFED_PORT_2	62
#define SCIF_OFED_PORT_3	63
#define SCIF_OFED_PORT_4	64
#define SCIF_OFED_PORT_5	65
#define SCIF_OFED_PORT_6	66
#define SCIF_OFED_PORT_7	67
#define SCIF_OFED_PORT_8	68
#define SCIF_OFED_PORT_9	69
#endif

#define IBSCIF_MTU	4096

#define IBSCIF_EP_TYPE_LISTEN	0
#define IBSCIF_EP_TYPE_COMM	1

#define DRV_NAME	"ibscif"
#define PFX		DRV_NAME ": "
#define	IBDEV_PFX	DRV_NAME ""
#define DRV_DESC	"OpenFabrics IBSCIF Driver"
#define DRV_VERSION	"0.2"
#define DRV_SIGNON	DRV_DESC " v" DRV_VERSION
#define DRV_RELDATE	"Oct 1, 2015"

#define UVERBS_ABI_VER	6
#define VENDOR_ID	0x8086	/* Intel Corporation */
#define DEVICE_ID	0
#define HW_REV		1
#define FW_REV		IBSCIF_PROTOCOL_VER

/*
 * Attribute limits.
 * These limits are imposed on client requests, however, the actual values
 * returned may be larger than these limits on some objects due to rounding.
 * The definitions are intended to show the thinking behind the values.
 * E.g., MAX_PDS defined as MAX_QPS is intended to allow each QP to be
 * on a separate PD, although that is not a usage requirement.
 */
#define	MAX_QPS		(64 * 1024)
#define	MAX_QP_SIZE	(16 * 1024)
#define	MAX_CQS		(MAX_QPS * 2)	  /* x2:send queues + recv queues */
#define	MAX_CQ_SIZE	(MAX_QP_SIZE * 4) /* or combined		  */
#define	MAX_PDS		MAX_QPS		  /* 1 per QP			  */
#define	MAX_MRS		16383		  /* limited by IBSCIF_MR_MAX_KEY */
#define	MAX_MR_SIZE	(2U * 1024 * 1024 * 1024)
#define	MAX_SGES	(PAGE_SIZE / sizeof(struct ib_sge))
#define	MAX_OR		(MAX_QP_SIZE / 2) /* half outbound reqs		  */
#define	MAX_IR		MAX_OR		  /* balance inbound with outbound*/

extern int window_size;
#define MIN_WINDOW_SIZE	4	/* Ack every window_size/MIN_WINDOW_SIZE packets */

extern int rma_threshold;
extern int fast_rdma;
extern int blocking_send;
extern int blocking_recv;
extern int scif_loopback;
extern int host_proxy;
extern int new_ib_type;
extern int verbose;
extern int check_grh;

extern struct list_head devlist;
extern struct mutex devlist_mutex;

extern struct idr wiremap;
extern rwlock_t wiremap_lock;

extern struct ib_dma_mapping_ops ibscif_dma_mapping_ops;

/* Match IB opcodes for copy in post_send; append driver specific values. */
enum ibscif_wr_opcode {
	WR_SEND			= IB_WR_SEND,
	WR_SEND_WITH_IMM	= IB_WR_SEND_WITH_IMM,
	WR_RDMA_WRITE		= IB_WR_RDMA_WRITE,
	WR_RDMA_WRITE_WITH_IMM	= IB_WR_RDMA_WRITE_WITH_IMM,
	WR_RDMA_READ		= IB_WR_RDMA_READ,
	WR_ATOMIC_CMP_AND_SWP	= IB_WR_ATOMIC_CMP_AND_SWP,
	WR_ATOMIC_FETCH_AND_ADD = IB_WR_ATOMIC_FETCH_AND_ADD,
	WR_RDMA_READ_RSP,
	WR_ATOMIC_RSP,
	WR_RMA_RSP,
	WR_UD,
	NR_WR_OPCODES		/* Must be last (for stats) */
};

struct ibscif_stats {
	unsigned long	packets_sent;
	unsigned long	packets_rcvd;
	unsigned long	bytes_sent;
	unsigned long	bytes_rcvd;
	unsigned long	duplicates;
	unsigned long	tx_errors;
	unsigned long	sched_exhaust;
	unsigned long	unavailable;
	unsigned long	loopback;
	unsigned long	recv;
	unsigned long	recv_imm;
	unsigned long	wr_opcode[NR_WR_OPCODES];
	unsigned long	fast_rdma_write;
	unsigned long	fast_rdma_read;
	unsigned long	fast_rdma_unavailable;
	unsigned long	fast_rdma_fallback;
	unsigned long	fast_rdma_force_ack;
	unsigned long	fast_rdma_tail_write;
};

#define	DEV_STAT(dev, counter)	dev->stats.counter

#define IBSCIF_MAX_DEVICES	16
#define IBSCIF_NAME_SIZE	12

#define IBSCIF_NODE_ID_TO_LID(node_id)	(node_id+1000)
#define IBSCIF_LID_TO_NODE_ID(lid)	(lid-1000)

struct ibscif_conn {
	struct list_head	entry;
	atomic_t		refcnt;
	scif_epd_t		ep;
	unsigned short		remote_node_id;
	union ib_gid		remote_gid;
	struct ibscif_dev	*dev;
	int			local_close;
	int			remote_close;
};

struct ibscif_listen {
	struct iw_cm_id		*cm_id;
	struct list_head	entry;
	struct kref		kref;
	int			port;
};

#define IBSCIF_MAX_PDATA_SIZE	256
struct ibscif_cm {
	struct iw_cm_id		*cm_id;
	struct ibscif_conn	*conn;
	struct ibscif_listen	*listen;
	struct kref		kref;
	spinlock_t		lock;
	struct sockaddr_in	local_addr;
	struct sockaddr_in	remote_addr;
	unsigned short		node_id;
	unsigned short		remote_node_id;
	u32			qpn;
	u32			remote_qpn;
	int			plen;
	u8			pdata[IBSCIF_MAX_PDATA_SIZE];
	u64			peer_context;
};

struct ibscif_dev {
	struct ib_device	ibdev;
	struct net_device	*netdev;	/* for RDMA CM support */
	struct list_head	entry;

	char			name[IBSCIF_NAME_SIZE];
	union ib_gid		gid;
	unsigned short		node_id;
	atomic_t		refcnt;
	scif_epd_t		listen_ep;
	struct list_head	conn_list;
	struct list_head	mr_list;
	struct mutex		mr_list_mutex;

	struct proc_dir_entry	*procfs;
	struct ibscif_stats	stats;

	atomic_t		pd_cnt;
	atomic_t		cq_cnt;
	atomic_t		qp_cnt;
	atomic_t		mr_cnt;

	atomic_t		available;
	atomic_t		was_new;

	spinlock_t		atomic_op;

	struct mutex		mutex;
	struct list_head	wq_list;	/* List of WQ's on this device */
};

struct ibscif_pd {
	struct ib_pd		ibpd;
};

struct ibscif_ah {
	struct ib_ah		ibah;
	__be16			dlid;
};

struct ibscif_wc {
	struct ib_wc		ibwc;
	int			reap;
	struct ibscif_wq	*wq;
};

enum ibscif_cq_state {
	CQ_READY,
	CQ_ERROR
};

struct ibscif_cq {
	struct ib_cq		ibcq;
	spinlock_t		lock;
	struct tasklet_struct	tasklet;
	enum ibscif_cq_state	state;
	enum ib_cq_notify_flags	arm;
	int			solicited;
	int			head;
	int			tail;
	int			depth;
	struct ibscif_wc	*wc;
};

struct ibscif_ds {
	struct ibscif_mr	*mr;
	u32			offset;
	u32			length;
	u32			lkey;
	u32			in_use;
	struct ibscif_mreg_info	*current_mreg;
};

struct ibscif_segmentation {
	struct ibscif_ds	*current_ds;
	u32			current_page_index;
	u32			current_page_offset;
	u32			wr_length_remaining;
	u32			ds_length_remaining;
	u32			starting_seq;
	u32			next_seq;
	u32			ending_seq;
};

struct ibscif_reassembly {
	struct ibscif_ds	*current_ds;
	u32			current_ds_offset;
	u32			last_packet_seq;
	u32			last_seen_seq;
	__be32			immediate_data;
	int			final_length;
	u16			opcode;
};

struct ibscif_sar {
	struct ibscif_segmentation seg;
	struct ibscif_reassembly  rea;
};

enum ibscif_wr_state {
	WR_WAITING,
	WR_STARTED,
	WR_WAITING_FOR_ACK,
	WR_WAITING_FOR_RSP,
	WR_LAST_SEEN,
	WR_COMPLETED
};

struct ibscif_wr {
	u64			id;
	enum ibscif_wr_opcode	opcode;
	int			length;
	enum ib_send_flags	flags;

	u32			msg_id;
	enum ibscif_wr_state	state;
	struct ibscif_sar	sar;
	u32			use_rma;
	u32			rma_id;

	union {
		struct ibscif_send {
			u32		immediate_data;
		} send;

		struct ibscif_ud {
			u16		remote_node_id;
			u32		remote_qpn;
		} ud;

		struct ibscif_read {
			u64		remote_address;
			int		remote_length;
			u32		rkey;
		} read;

		struct ibscif_write {
			u64		remote_address;
			u32		rkey;
			u32		immediate_data;
		} write;

		struct ibscif_cmp_swp {
			u64		cmp_operand;
			u64		swp_operand;
			u64		remote_address;
			u32		rkey;
		} cmp_swp;

		struct ibscif_fetch_add {
			u64		add_operand;
			u64		remote_address;
			u32		rkey;
		} fetch_add;

		struct ibscif_atomic_rsp {
			u64		orig_data;
			u16		opcode;
		} atomic_rsp;

		struct ibscif_rma_rsp {
			u32		xfer_length;
			u32		error;
		} rma_rsp;
	};

	u32			num_ds;
	struct ibscif_ds		ds_list[0];	/* Must be last */
};

struct ibscif_tx_state {
	u32			next_seq;
	u32			last_ack_seq_recvd;
	u32			next_msg_id;
};

struct ibscif_rx_state {
	u32			last_in_seq;
	u32			last_seq_acked;
	int			defer_in_process;
};

struct ibscif_wirestate {
	struct ibscif_tx_state	tx;
	struct ibscif_rx_state	rx;
};

struct ibscif_wire {
	struct ibscif_wirestate	sq;
	struct ibscif_wirestate	iq;
};

struct ibscif_wq {
	struct list_head	entry;
	struct ibscif_qp	*qp;
	spinlock_t		lock;
	struct ibscif_wr	*wr;
	int			head;
	int			tail;
	int			depth;
	int			size;
	int			max_sge;
	int			wr_size;
	int			completions;
	int			reap;
	int			next_wr;
	int			next_msg_id;
	struct ibscif_wirestate	*wirestate;
	int			fast_rdma_completions;
	int			ud_msg_id;
};

enum ibscif_qp_state {
	QP_IDLE,
	QP_CONNECTED,
	QP_DISCONNECT,
	QP_ERROR,
	QP_RESET,
	QP_IGNORE,
	NR_QP_STATES		/* Must be last */
};

enum ibscif_schedule {
	SCHEDULE_RESUME	 = 1 << 0,
	SCHEDULE_RETRY	 = 1 << 1,
	SCHEDULE_TIMEOUT = 1 << 2,
	SCHEDULE_SQ	 = 1 << 6,
	SCHEDULE_IQ	 = 1 << 7
};

struct ibscif_qp {
	int			magic;		/* Must be first */
#	define QP_MAGIC		0x5b51505d	/*    "[QP]"     */
	struct kref		ref;
	struct completion	done;
	struct ib_qp		ibqp;
	struct ibscif_dev	*dev;
	enum ib_access_flags	access;
	enum ib_sig_type	sq_policy;
	enum ibscif_schedule	schedule;
	struct ibscif_wire	wire;
	int			mtu;

	int			max_or;
	atomic_t		or_depth;
	atomic_t		or_posted;

	struct mutex		modify_mutex;
	spinlock_t		lock;
	enum ibscif_qp_state	state;
	u16			local_node_id;
	u16			remote_node_id;
	struct ibscif_conn	*conn;
	u32			remote_qpn;
	int			loopback;
	struct ibscif_wq	sq;
	struct ibscif_wq	rq;
	struct ibscif_wq	iq;
	int			in_scheduler;

	struct ibscif_conn	*ud_conn[IBSCIF_MAX_DEVICES];
	struct ibscif_cm	*cm_context;
};

#define	is_sq(wq)		(wq == &wq->qp->sq)
#define	is_rq(wq)		(wq == &wq->qp->rq)
#define	is_iq(wq)		(wq == &wq->qp->iq)

/* Info about MR registered via SCIF API */
struct ibscif_mreg_info {
	struct list_head	entry;
	struct ibscif_conn	*conn;
	u64			offset;
	u64			aligned_offset;
	u32			aligned_length;
};

struct ibscif_mr {
	int			magic;		/* Must be first */
#	define MR_MAGIC		0x5b4d525d	/*    "[MR]"     */
	struct list_head	entry;
	struct kref		ref;
	struct completion	done;
	struct ib_mr		ibmr;
	struct ib_umem		*umem;
	enum ib_access_flags	access;
	u64			addr;
	u32			length;
	int			npages;
	struct page		**page;
	scif_pinned_pages_t	pinned_pages;
	struct list_head	mreg_list;
};

/* Canonical virtual address on X86_64 falls in the range 0x0000000000000000-0x00007fffffffffff
 * and 0xffff800000000000-0xffffffffffffffff. The range 0x0000800000000000-0xffff7fffffffffff
 * are unused. This basically means only 48 bits are used and the highest 16 bits are just sign
 * extensions. We can put rkey into these 16 bits and use the result as the "offset" of SCIF's
 * registered address space. By doing this, the SCIF_MAP_FIXED flag can be used so that the offset
 * can be calculated directly from rkey and virtual address w/o using the "remote registration cache"
 * mechanism.
 *
 * SCIF reserve the top 2 bits of the offset for internal uses, leaving 14 bits for rkey.
 */
#define IBSCIF_MR_MAX_KEY	(0x3FFF)
#define IBSCIF_MR_VADDR_MASK	(0x0000FFFFFFFFFFFFUL)
#define IBSCIF_MR_SIGN_MASK	(0x0000800000000000UL)
#define IBSCIF_MR_SIGN_EXT	(0xFFFF000000000000UL)
#define IBSCIF_MR_RKEY_MASK	(0x3FFF000000000000UL)

#define IBSCIF_MR_VADDR_TO_OFFSET(rkey, vaddr)	((((unsigned long)rkey) << 48) | \
						 (vaddr & IBSCIF_MR_VADDR_MASK))

#define IBSCIF_MR_OFFSET_TO_VADDR(offset)	((offset & IBSCIF_MR_SIGN_MASK) ? \
						 (offset | IBSCIF_MR_SIGN_EXT) : \
						 (offset & IBSCIF_MR_VADDR_MASK))

#define IBSCIF_MR_OFFSET_TO_RKEY(offset)	((offset & IBSCIF_MR_RKEY_MASK) >> 48)

#define	TO_OBJ(name, src, dst, field)				\
static inline struct dst *name(struct src *field)		\
{								\
	return container_of(field, struct dst, field);		\
}
TO_OBJ(to_dev, ib_device, ibscif_dev, ibdev)
TO_OBJ(to_pd, ib_pd, ibscif_pd, ibpd)
TO_OBJ(to_cq, ib_cq, ibscif_cq, ibcq)
TO_OBJ(to_qp, ib_qp, ibscif_qp, ibqp)
TO_OBJ(to_mr, ib_mr, ibscif_mr, ibmr)
TO_OBJ(to_ah, ib_ah, ibscif_ah, ibah)

#define OBJ_GET(obj, type)					\
static inline struct ibscif_##obj *ibscif_get_##obj(int id)	\
{								\
	struct ibscif_##obj *obj;				\
	read_lock_bh(&wiremap_lock);				\
	obj = idr_find(&wiremap, id);				\
	if (likely(obj)) {					\
		if (likely(obj->magic == type))			\
			kref_get(&obj->ref);			\
		else						\
			obj = ERR_PTR(-ENXIO);			\
	} else							\
		obj = ERR_PTR(-ENOENT);				\
	read_unlock_bh(&wiremap_lock);				\
	return obj;						\
}
OBJ_GET(mr, MR_MAGIC)
OBJ_GET(qp, QP_MAGIC)

void ibscif_complete_mr(struct kref *kref);
void ibscif_complete_qp(struct kref *kref);

#define OBJ_PUT(obj)						\
static inline void ibscif_put_##obj(struct ibscif_##obj *obj)	\
{								\
	if (likely(obj))					\
		kref_put(&obj->ref, ibscif_complete_##obj);	\
}
OBJ_PUT(mr)
OBJ_PUT(qp)

/* This function assumes the WQ is protected by a lock. */
static inline struct ibscif_wr *ibscif_get_wr(struct ibscif_wq *wq, int index)
{
	/* Must calculate because WQ array elements are variable sized. */
	return (struct ibscif_wr *)((void *)wq->wr + (wq->wr_size * index));
}

/* This function assumes the WQ is protected by a lock. */
static inline void ibscif_append_wq(struct ibscif_wq *wq)
{
	wq->tail = (wq->tail + 1) % wq->size;
	wq->depth++;
	wq->next_msg_id++;
}

static inline void ibscif_clear_ds_ref(struct ibscif_ds *ds)
{
	if (ds->in_use) {
		ds->in_use = 0;
		ibscif_put_mr(ds->mr);
	}
}

static inline void ibscif_clear_ds_refs(struct ibscif_ds *ds, int num_ds)
{
	while(num_ds--)
		ibscif_clear_ds_ref(ds++);
}

static inline enum ib_wc_opcode to_ib_wc_opcode(enum ib_wr_opcode opcode)
{
	/* SQ only - RQ is either IB_WC_RECV or IB_WC_RECV_RDMA_WITH_IMM. */
	switch (opcode) {
	case IB_WR_RDMA_WRITE:		 return IB_WC_RDMA_WRITE;
	case IB_WR_RDMA_WRITE_WITH_IMM:	 return IB_WC_RDMA_WRITE;
	case IB_WR_SEND:		 return IB_WC_SEND;
	case IB_WR_SEND_WITH_IMM:	 return IB_WC_SEND;
	case IB_WR_RDMA_READ:		 return IB_WC_RDMA_READ;
	case IB_WR_ATOMIC_CMP_AND_SWP:	 return IB_WC_COMP_SWAP;
	case IB_WR_ATOMIC_FETCH_AND_ADD: return IB_WC_FETCH_ADD;
	default:			 return -1;
	}
}

static inline void *ibscif_map_src(struct page *page)
{
	return kmap_atomic(page);
}

static inline void *ibscif_map_dst(struct page *page)
{
	return kmap_atomic(page);
}

static inline void ibscif_unmap_src(struct page *page, void *addr)
{
	if (likely(addr))
		kunmap_atomic(addr);
}

static inline void ibscif_unmap_dst(struct page *page, void *addr)
{
	if (likely(addr))
		kunmap_atomic(addr);
	if (likely(page)) {
		flush_dcache_page(page);
		if (!PageReserved(page))
			set_page_dirty(page);
	}
}

#ifdef IBSCIF_PERF_TEST
#define IBSCIF_PERF_SAMPLE(counter,next) ibscif_perf_sample(counter,next)
#else
#define IBSCIF_PERF_SAMPLE(counter,next)
#endif

int ibscif_atomic_copy(void *dst_addr, void *src_addr, u32 copy_len, int head_copied);

int ibscif_wiremap_add(void *obj, int *id);
void ibscif_wiremap_del(int id);

int ibscif_dev_init(void);
void ibscif_protocol_init_pre(void);
void ibscif_protocol_init_post(void);

void ibscif_dev_cleanup(void);
void ibscif_protocol_cleanup(void);

int ibscif_procfs_add_dev(struct ibscif_dev *dev);
void ibscif_procfs_remove_dev(struct ibscif_dev *dev);

int ibscif_reserve_quota(int *npages);
void ibscif_release_quota(int npages);

void ibscif_scheduler_add_qp(struct ibscif_qp *qp);
void ibscif_scheduler_remove_qp(struct ibscif_qp *qp);
void ibscif_schedule(struct ibscif_wq *wq);

struct ib_ah *ibscif_create_ah(struct ib_pd *ibpd, struct ib_ah_attr *attr);
int ibscif_destroy_ah(struct ib_ah *ibah);

struct ib_pd *ibscif_alloc_pd(struct ib_device *ibdev, struct ib_ucontext *context, struct ib_udata *udata);
int ibscif_dealloc_pd(struct ib_pd *ibpd);

struct ib_qp *ibscif_create_qp(struct ib_pd *ibpd, struct ib_qp_init_attr *attr, struct ib_udata *udata);
int ibscif_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask, struct ib_qp_init_attr *init_attr);
int ibscif_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask, struct ib_udata *udata);
int ibscif_destroy_qp(struct ib_qp *ibqp);
void ibscif_qp_internal_disconnect(struct ibscif_qp *qp, enum ibscif_reason reason);
void ibscif_qp_remote_disconnect(struct ibscif_qp *qp, enum ibscif_reason reason);
void ibscif_qp_add_ud_conn(struct ibscif_qp *qp, struct ibscif_conn *conn);

struct ib_cq *ibscif_create_cq(struct ib_device *ibdev, const struct ib_cq_init_attr *attr,
			      struct ib_ucontext *context, struct ib_udata *udata);
int ibscif_resize_cq(struct ib_cq *ibcq, int cqe, struct ib_udata *udata);
int ibscif_destroy_cq(struct ib_cq *ibcq);
int ibscif_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *entry);
int ibscif_arm_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags notify);
void ibscif_notify_cq(struct ibscif_cq *cq);
void ibscif_clear_cqes(struct ibscif_cq *cq, struct ibscif_wq *wq);
int ibscif_reserve_cqe(struct ibscif_cq *cq, struct ibscif_wc **wc);
void ibscif_append_cqe(struct ibscif_cq *cq, struct ibscif_wc *wc, int solicited);

struct ib_mr *ibscif_get_dma_mr(struct ib_pd *ibpd, int access);
struct ib_mr *ibscif_reg_phys_mr(struct ib_pd *ibpd, struct ib_phys_buf *phys_buf_array,
				int num_phys_buf, int access, u64 *iova_start);
struct ib_mr *ibscif_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 length,
				u64 virt_addr, int access, struct ib_udata *udata);
int ibscif_dereg_mr(struct ib_mr *ibmr);
struct ibscif_mr *ibscif_validate_mr(u32 key, u64 addr, int length,
				   struct ib_pd *ibpd, enum ib_access_flags access);
struct ibscif_mreg_info *ibscif_mr_get_mreg(struct ibscif_mr *mr, struct ibscif_conn *conn);
void ibscif_refresh_mreg( struct ibscif_conn *conn );

int ibscif_post_send(struct ib_qp *ibqp, struct ib_send_wr *ibwr, struct ib_send_wr **bad_wr);
int ibscif_post_receive(struct ib_qp *ibqp, struct ib_recv_wr *ibwr, struct ib_recv_wr **bad_wr);

void ibscif_send_disconnect(struct ibscif_qp *qp, enum ibscif_reason reason);
void ibscif_send_close(struct ibscif_conn *conn);
void ibscif_send_reopen(struct ibscif_conn *conn);

void ibscif_loopback_disconnect(struct ibscif_qp *qp, enum ibscif_reason reason);
void ibscif_loopback(struct ibscif_wq *sq);

int ibscif_xmit_wr(struct ibscif_wq *wq, struct ibscif_wr *wr, int tx_limit, int retransmit,
		  u32 from_seq, u32 *posted);
int ibscif_process_sq_completions(struct ibscif_qp *qp);

struct ibscif_conn *ibscif_get_conn( int node_id, int remote_node_id, int find_local_peer );
void ibscif_put_conn( struct ibscif_conn *conn );
void ibscif_do_accept(struct ibscif_dev *dev);
void ibscif_get_pollep_list(struct scif_pollepd *polleps, struct ibscif_dev **devs,
			  int *types, struct ibscif_conn **conns, int *count);
void ibscif_refresh_pollep_list(void);
void ibscif_get_ep_list(scif_epd_t *eps, int *count);
void ibscif_remove_ep(struct ibscif_dev *dev, scif_epd_t ep);
void ibscif_free_conn(struct ibscif_conn *conn);
int  ibscif_cleanup_idle_conn( void );
void ibscif_perf_sample(int counter, int next);

int ibscif_cm_connect(struct iw_cm_id *cm_id, struct iw_cm_conn_param *conn_param);
int ibscif_cm_accept(struct iw_cm_id *cm_id, struct iw_cm_conn_param *conn_param);
int ibscif_cm_reject(struct iw_cm_id *cm_id, const void *pdata, u8 pdata_len);
int ibscif_cm_create_listen(struct iw_cm_id *cm_id, int backlog);
int ibscif_cm_destroy_listen(struct iw_cm_id *cm_id);
struct ib_qp *ibscif_cm_get_qp(struct ib_device *ibdev, int qpn);
void ibscif_cm_add_ref(struct ib_qp *ibqp);
void ibscif_cm_rem_ref(struct ib_qp *ibqp);
void ibscif_cm_async_callback(void *cm_context);
int ibscif_process_cm_skb(struct sk_buff *skb, struct ibscif_conn *conn);
int ibscif_send_cm_req(struct ibscif_cm *cm_ctx);
int ibscif_send_cm_rep(struct ibscif_cm *cm_ctx);
int ibscif_send_cm_rej(struct ibscif_cm *cm_ctx, const void *pdata, u8 plen);
int ibscif_send_cm_rtu(struct ibscif_cm *cm_ctx);

#endif /* IBSCIF_DRIVER_H */
