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

#define IBSCIF_CONN_IDLE 0
#define IBSCIF_CONN_REQ_SENT 1
#define IBSCIF_CONN_REQ_RCVD 2
#define IBSCIF_CONN_ESTABLISHED 3
#define IBSCIF_CONN_ACTIVE 4

DEFINE_SPINLOCK(conn_state_lock);
static int conn_state[IBSCIF_MAX_DEVICES][IBSCIF_MAX_DEVICES];

#define IBSCIF_CONN_REP 1
#define IBSCIF_CONN_REJ 2
#define IBSCIF_CONN_ERR 3

struct ibscif_conn_resp {
	int cmd;
	union ib_gid gid;
};

void ibscif_do_accept(struct ibscif_dev *dev)
{
	struct scif_port_id peer;
	scif_epd_t ep;
	struct ibscif_conn *conn;
	int ret;
	struct ibscif_conn_resp resp;
	int resp_size;

	if (check_grh)
		resp_size = sizeof(resp);
	else
		resp_size = sizeof(int);

	ret = scif_accept(dev->listen_ep, &peer, &ep, SCIF_ACCEPT_SYNC);
	if (ret) {
		printk(KERN_ALERT PFX "%s: scif_accept returns %ld\n",
			__func__, PTR_ERR(ep));
		return;
	}

	if (verbose)
		printk(KERN_INFO PFX "%s: %d<--%d\n",
			__func__, dev->node_id, peer.node);

	if (check_grh)
		memcpy(&resp.gid, &dev->gid, sizeof(resp.gid));

	spin_lock(&conn_state_lock);
	switch (conn_state[dev->node_id][peer.node]) {
	  case IBSCIF_CONN_IDLE:
		conn_state[dev->node_id][peer.node] = IBSCIF_CONN_REQ_RCVD;
		resp.cmd = IBSCIF_CONN_REP;
		if (verbose)
			printk(KERN_INFO PFX
				"%s: no double connection, accepting\n",
				__func__);
		break;

	  case IBSCIF_CONN_REQ_SENT:
		/* A connection request has been sent, but no response yet.
		 * Node id is used to break the tie when both side send the
		 * connection request. One side is allowed to accept the
		 * request and its own request will be rejected by the peer.
		 */
		if (dev->node_id > peer.node) {
			resp.cmd = IBSCIF_CONN_REJ;
			if (verbose)
				printk(KERN_INFO PFX
					"%s: double connection, rejecting "
					"(peer will accept)\n", __func__);
		}
		else if (dev->node_id == peer.node) {
			conn_state[dev->node_id][peer.node] =
				IBSCIF_CONN_REQ_RCVD;
			resp.cmd = IBSCIF_CONN_REP;
			if (verbose)
				printk(KERN_INFO PFX
					"%s: loopback connection, accepting\n",
					__func__);
		}
		else {
			conn_state[dev->node_id][peer.node] =
				IBSCIF_CONN_REQ_RCVD;
			resp.cmd = IBSCIF_CONN_REP;
			if (verbose)
				printk(KERN_INFO PFX
					"%s: double connection, accepting "
					"(peer will reject)\n", __func__);
		}
		break;

	  case IBSCIF_CONN_REQ_RCVD:
		if (verbose)
			printk(KERN_INFO PFX
				"%s: duplicated connection request, "
				"rejecting\n", __func__);
		resp.cmd = IBSCIF_CONN_REJ;
		break;

	  case IBSCIF_CONN_ESTABLISHED:
	  case IBSCIF_CONN_ACTIVE:
		if (verbose)
			printk(KERN_INFO PFX
				"%s: already connected, rejecting\n",
				__func__);
		resp.cmd = IBSCIF_CONN_REJ;
		break;

	  default:
		if (verbose)
			printk(KERN_INFO PFX "%s: invalid state: %d\n",
				__func__, conn_state[dev->node_id][peer.node]);
		resp.cmd = IBSCIF_CONN_ERR;
		break;
	}
	spin_unlock(&conn_state_lock);

	ret = scif_send(ep, &resp, resp_size, SCIF_SEND_BLOCK);
	if (ret < 0) {
		printk(KERN_ALERT PFX "%s: scif_send returns %d\n",
			__func__, ret);
		scif_close(ep);
		return;
	}

	if (resp.cmd != IBSCIF_CONN_REP) {
		/* one additional hand shaking to prevent the previous
		 * send from being trashed by ep closing
		 */
		scif_recv(ep, &resp, resp_size, SCIF_RECV_BLOCK);
		scif_close(ep);
		return;
	}

	if (check_grh) {
		ret = scif_recv(ep, &resp, resp_size, SCIF_RECV_BLOCK);
		if (ret < 0) {
			printk(KERN_ALERT PFX "%s: scif_recv returns %d\n",
				__func__, ret);
			scif_close(ep);
			spin_lock(&conn_state_lock);
			conn_state[dev->node_id][peer.node] = IBSCIF_CONN_IDLE;
			spin_unlock(&conn_state_lock);
			return;
		}
	}

	conn = kzalloc(sizeof (*conn), GFP_KERNEL);
	if (!conn) {
		printk(KERN_ALERT PFX
			"%s: cannot allocate connection context.\n", __func__);
		scif_close(ep);
		spin_lock(&conn_state_lock);
		conn_state[dev->node_id][peer.node] = IBSCIF_CONN_IDLE;
		spin_unlock(&conn_state_lock);
		return;
	}

	conn->ep = ep;
	conn->remote_node_id = peer.node;
	if (check_grh)
		memcpy(&conn->remote_gid, &resp.gid, sizeof(conn->remote_gid));
	conn->dev = dev;
	atomic_set(&conn->refcnt, 0);

	spin_lock(&conn_state_lock);
	conn_state[dev->node_id][peer.node] = IBSCIF_CONN_ESTABLISHED;
	spin_unlock(&conn_state_lock);

	if (verbose)
		printk(KERN_INFO PFX "%s: connection established. ep=%p\n",
			__func__, ep);

	ibscif_refresh_mreg(conn);

	/* one addition sync to ensure the MRs are registered with the
	 * new ep at both side
	 */
	scif_send(ep, &resp, resp_size, SCIF_SEND_BLOCK);
	scif_recv(ep, &resp, resp_size, SCIF_RECV_BLOCK);

	list_add(&conn->entry, &dev->conn_list);
	ibscif_refresh_pollep_list();

	spin_lock(&conn_state_lock);
	conn_state[dev->node_id][peer.node] = IBSCIF_CONN_ACTIVE;
	spin_unlock(&conn_state_lock);
}

static struct ibscif_conn *ibscif_do_connect(struct ibscif_dev *dev,
					     int remote_node_id)
{
	struct scif_port_id dest;
	struct ibscif_conn *conn = NULL;
	int ret;
	scif_epd_t ep;
	struct ibscif_conn_resp resp;
	union ib_gid peer_gid;
	int resp_size;

	if (check_grh)
		resp_size = sizeof(resp);
	else
		resp_size = sizeof(int);

	if (verbose)
		printk(KERN_INFO PFX "%s: %d-->%d\n",
			__func__, dev->node_id, remote_node_id);

	/* Validate remote_node_id for conn_state array check */
	if ((remote_node_id < 0) || (remote_node_id >= IBSCIF_MAX_DEVICES))
		return ERR_PTR(-EINVAL);

	spin_lock(&conn_state_lock);
	if (conn_state[dev->node_id][remote_node_id] != IBSCIF_CONN_IDLE) {
		spin_unlock(&conn_state_lock);
		if (verbose)
			printk(KERN_INFO PFX
				"%s: connection already in progress, retry\n",
				__func__);
		return ERR_PTR(-EAGAIN);
	}
	conn_state[dev->node_id][remote_node_id] = IBSCIF_CONN_REQ_SENT;
	spin_unlock(&conn_state_lock);

	ep = scif_open();
	if (!ep) /* SCIF API semantics */
		goto out_state;

	if (IS_ERR(ep)) /* SCIF emulator semantics */
		goto out_state;

	dest.node = remote_node_id;
	dest.port = SCIF_OFED_PORT_0;

	ret = scif_connect(ep, &dest);
	if (ret < 0)
		goto out_close;

	/* Now ret is the port number ep is bound to */

	ret = scif_recv(ep, &resp, resp_size, SCIF_RECV_BLOCK);
	if (ret < 0) {
		printk(KERN_ALERT PFX "%s: scif_recv returns %d\n",
			__func__, ret);
		goto out_close;
	}

	if (resp.cmd != IBSCIF_CONN_REP) {
		scif_send(ep, &resp, resp_size, SCIF_SEND_BLOCK);
		/* the peer has issued the connection request */
		if (resp.cmd == IBSCIF_CONN_REJ) {
			if (verbose)
				printk(KERN_INFO PFX
					"%s: rejected by peer due to "
					"double connection\n", __func__);
			scif_close(ep);
			/* don't reset the state becasue it's used for
			 * checking connection state
			 */
			return ERR_PTR(-EAGAIN);
		}
		else {
			if (verbose)
				printk(KERN_INFO PFX
					"%s: rejected by peer due to "
					"invalid state\n", __func__);
			goto out_close;
		}
	}

	if (check_grh) {
		memcpy(&peer_gid, &resp.gid, sizeof(peer_gid));
		memcpy(&resp.gid, &dev->gid, sizeof(resp.gid));
		ret = scif_send(ep, &resp, resp_size, SCIF_SEND_BLOCK);
		if (ret < 0) {
			printk(KERN_ALERT PFX "%s: scif_send returns %d\n",
				__func__, ret);
			goto out_close;
		}
	}

	if (verbose)
		printk(KERN_INFO PFX "%s: connection established. ep=%p\n",
			__func__, ep);

	spin_lock(&conn_state_lock);
	conn_state[dev->node_id][remote_node_id] = IBSCIF_CONN_ESTABLISHED;
	spin_unlock(&conn_state_lock);

	conn = kzalloc(sizeof *conn, GFP_KERNEL);
	if (!conn) {
		printk(KERN_ALERT PFX
			"%s: failed to allocate connection object\n", __func__);
		goto out_close;
	}

	conn->ep = ep;
	conn->remote_node_id = remote_node_id;
	if (check_grh)
		memcpy(&conn->remote_gid, &peer_gid, sizeof(conn->remote_gid));
	conn->dev = dev;
	atomic_set(&conn->refcnt, 0);

	ibscif_refresh_mreg(conn);

	/* one addition sync to ensure the MRs are registered with the new
	 * ep at both side
	 */
	scif_send(ep, &resp, resp_size, SCIF_SEND_BLOCK);
	scif_recv(ep, &resp, resp_size, SCIF_RECV_BLOCK);

	list_add_tail(&conn->entry, &dev->conn_list);
	ibscif_refresh_pollep_list();

	spin_lock(&conn_state_lock);
	conn_state[dev->node_id][remote_node_id] = IBSCIF_CONN_ACTIVE;
	spin_unlock(&conn_state_lock);

	return conn;

out_close:
	scif_close(ep);

out_state:
	spin_lock(&conn_state_lock);
	if (conn_state[dev->node_id][remote_node_id] == IBSCIF_CONN_REQ_SENT)
		conn_state[dev->node_id][remote_node_id] = IBSCIF_CONN_IDLE;
	spin_unlock(&conn_state_lock);
	return conn;
}

struct ibscif_conn *ibscif_get_conn(int node_id, int remote_node_id,
				    int find_local_peer)
{
	struct ibscif_dev *cur, *next, *dev = NULL;
	struct ibscif_conn *conn, *conn1, *conn2;
	int done=0, err=0, connect_tried=0;

	mutex_lock(&devlist_mutex);
	list_for_each_entry_safe(cur, next, &devlist, entry) {
		if (cur->node_id == node_id) {
			dev = cur;
			break;
		}
	}
	mutex_unlock(&devlist_mutex);

	if (!dev)
		return NULL;

again:
	conn1 = NULL;
	conn2 = NULL;
	mutex_lock(&dev->mutex);
	list_for_each_entry(conn, &dev->conn_list, entry)
	{
		if (conn->remote_node_id == remote_node_id) {
			if (node_id == remote_node_id) {
				if (!conn1) {
					conn1 = conn;
					continue;
				}
				else {
					conn2 = conn;
					break;
				}
			}
			mutex_unlock(&dev->mutex);
			atomic_inc(&conn->refcnt);
			if (conn->local_close) {
				conn->local_close = 0;
				ibscif_send_reopen(conn);
			}
			return conn;
		}
	}
	mutex_unlock(&dev->mutex);

	/* for loopback connections, we must wait for both endpoints be in
	 * the list to ensure that different endpoints are assigned to the
	 * two sides.
	 */
	if (node_id == remote_node_id) {
		if (conn1 && conn2) {
			conn = find_local_peer ? conn2 : conn1;
			atomic_inc(&conn->refcnt);
			if (conn->local_close) {
				conn->local_close = 0;
				ibscif_send_reopen(conn);
			}
			return conn;
		}
		else if (conn1) {
			schedule();
			goto again;
		}
	}

	if (connect_tried) {
		printk(KERN_ALERT PFX
			"%s: ERROR: cannot get connection (%d-->%d) after "
			"waiting, state=%d\n",
			__func__, dev->node_id, remote_node_id, err-1);
		return NULL;
	}

	conn = ibscif_do_connect(dev, remote_node_id);

	/* If a connection is in progress, wait for its finish */
	if (conn == ERR_PTR(-EAGAIN)) {
	    while (!done && !err) {
		spin_lock(&conn_state_lock);
		switch (conn_state[node_id][remote_node_id]) {
		  case IBSCIF_CONN_REQ_SENT:
		  case IBSCIF_CONN_REQ_RCVD:
		  case IBSCIF_CONN_ESTABLISHED:
			break;
		  case IBSCIF_CONN_ACTIVE:
			done = 1;
			break;
		  default:
			err = 1 + conn_state[node_id][remote_node_id];
			break;
		}
		spin_unlock(&conn_state_lock);
		schedule();
	    }
	}

	connect_tried = 1;
	goto again;
}

void ibscif_put_conn(struct ibscif_conn *conn)
{
	if (!conn)
		return;

	if (atomic_dec_and_test(&conn->refcnt)) {
		ibscif_send_close(conn);
		conn->local_close = 1;
	}
}

void ibscif_get_pollep_list(struct scif_pollepd *polleps,
			    struct ibscif_dev **devs, int *types,
			    struct ibscif_conn **conns, int *count)
{
	struct ibscif_dev *dev;
	struct ibscif_conn *conn;
	int i = 0;
	int max = *count;

	mutex_lock(&devlist_mutex);
	list_for_each_entry(dev, &devlist, entry) {
		if (i >= max)
			break;

		polleps[i].epd = dev->listen_ep;
		polleps[i].events = POLLIN;
		polleps[i].revents = 0;
		devs[i] = dev;
		types[i] = IBSCIF_EP_TYPE_LISTEN;
		conns[i] = NULL;
		i++;
		if (verbose)
			printk(KERN_INFO PFX "%s: ep=%p (%d:listen)\n",
				__func__, dev->listen_ep, dev->node_id);

		mutex_lock(&dev->mutex);
		list_for_each_entry(conn, &dev->conn_list, entry)
		{
			if (i >= max)
				break;
			polleps[i].epd = conn->ep;
			polleps[i].events = POLLIN;
			polleps[i].revents = 0;
			devs[i] = dev;
			types[i] = IBSCIF_EP_TYPE_COMM;
			conns[i] = conn;
			i++;
			if (verbose)
				printk(KERN_INFO PFX "%s: ep=%p (%d<--->%d)\n",
					__func__, conn->ep, dev->node_id,
					conn->remote_node_id);
		}
		mutex_unlock(&dev->mutex);
	}
	mutex_unlock(&devlist_mutex);

	if (verbose)
		printk(KERN_INFO PFX "%s: count=%d\n", __func__, i);
	*count = i;
}

void ibscif_get_ep_list(scif_epd_t *eps, int *count)
{
	struct ibscif_dev *dev;
	struct ibscif_conn *conn;
	int i = 0;
	int max = *count;

	mutex_lock(&devlist_mutex);
	list_for_each_entry(dev, &devlist, entry) {
		if (i >= max)
			break;

		mutex_lock(&dev->mutex);
		list_for_each_entry(conn, &dev->conn_list, entry)
		{
			if (i >= max)
				break;
			eps[i] = conn->ep;
			i++;
		}
		mutex_unlock(&dev->mutex);
	}
	mutex_unlock(&devlist_mutex);

	*count = i;
}

void ibscif_remove_ep(struct ibscif_dev *dev, scif_epd_t ep)
{
	struct ibscif_conn *conn, *next;
	mutex_lock(&dev->mutex);
	list_for_each_entry_safe(conn, next, &dev->conn_list, entry)
	{
		if (conn->ep == ep) {
			spin_lock(&conn_state_lock);
			conn_state[conn->dev->node_id][conn->remote_node_id] =
				IBSCIF_CONN_IDLE;
			spin_unlock(&conn_state_lock);
			list_del(&conn->entry);
		}
	}
	mutex_unlock(&dev->mutex);
}


void ibscif_free_conn(struct ibscif_conn *conn)
{
	scif_close(conn->ep);
	kfree(conn);
}

int ibscif_cleanup_idle_conn(void)
{
	struct ibscif_dev *dev;
	struct ibscif_conn *conn, *next;
	struct ibscif_conn *idle_conns[IBSCIF_MAX_DEVICES];
	int i, n=0;

	mutex_lock(&devlist_mutex);
	list_for_each_entry(dev, &devlist, entry) {
		mutex_lock(&dev->mutex);
		list_for_each_entry_safe(conn, next, &dev->conn_list, entry)
		{
			if (conn->local_close && conn->remote_close) {
				spin_lock(&conn_state_lock);
				conn_state[conn->dev->node_id][
					conn->remote_node_id] =
						IBSCIF_CONN_IDLE;
				spin_unlock(&conn_state_lock);
				list_del(&conn->entry);
				idle_conns[n++] = conn;
			}
		}
		mutex_unlock(&dev->mutex);
	}
	mutex_unlock(&devlist_mutex);

	for (i=0; i<n; i++)
		ibscif_free_conn(idle_conns[i]);

	if (n && verbose)
		printk(KERN_ALERT PFX "%s: n=%d\n", __func__, n);

	return n;
}

/*
 * Simple routines to support performance profiling
 */

#include <linux/time.h>

static uint32_t ibscif_time_passed(void)
{
	static int first = 1;
	static struct timeval t0;
	static struct timeval t;
	uint32_t usec;

	if (first) {
		do_gettimeofday(&t0);
		first = 0;
		return 0;
	}

	do_gettimeofday(&t);
	usec = (t.tv_sec - t0.tv_sec) * 1000000UL;
	if (t.tv_usec >= t0.tv_usec)
		usec += (t.tv_usec - t0.tv_usec);
	else
		usec -= (t0.tv_usec - t.tv_usec);

	t0 = t;
	return usec;
}

#define IBSCIF_PERF_MAX_SAMPLES		100
#define IBSCIF_PERF_MAX_COUNTERS	10

void ibscif_perf_sample(int counter, int next)
{
	static uint32_t T[IBSCIF_PERF_MAX_SAMPLES][IBSCIF_PERF_MAX_COUNTERS];
	static int T_idx=0;
	int i, j, sum;

	if (counter>=0 && counter<IBSCIF_PERF_MAX_COUNTERS)
		T[T_idx][counter] = ibscif_time_passed();

	if (next) {
		if (++T_idx < IBSCIF_PERF_MAX_SAMPLES)
			return;

		T_idx = 0;

		/* batch output to minimize the impact on higher level timing */
		for (i=0; i<IBSCIF_PERF_MAX_SAMPLES; i++) {
			sum = 0;
			printk(KERN_INFO PFX "%d: ", i);
			for (j=0; j<IBSCIF_PERF_MAX_COUNTERS; j++) {
				printk("T%d=%u ", j, T[i][j]);
				if (j>0)
					sum += T[i][j];
			}
			printk("SUM(T1..T%d)=%u\n",
				IBSCIF_PERF_MAX_COUNTERS-1, sum);
		}
	}
}

