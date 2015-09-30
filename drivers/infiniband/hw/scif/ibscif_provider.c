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

static int ibscif_query_device(struct ib_device *ibdev,
			       struct ib_device_attr *attr,
			       struct ib_udata *udata)
{
	if (udata->inlen || udata->outlen)
		return -EINVAL;

	memset(attr, 0, sizeof *attr);

	attr->vendor_id           = VENDOR_ID;
	attr->vendor_part_id      = DEVICE_ID;
	attr->hw_ver              = HW_REV;
	attr->fw_ver              = FW_REV;
	attr->device_cap_flags    = IB_DEVICE_PORT_ACTIVE_EVENT;
	attr->max_mr_size         = MAX_MR_SIZE;
	attr->page_size_cap       = PAGE_SIZE;
	attr->max_qp              = MAX_QPS;
	attr->max_qp_wr           = MAX_QP_SIZE;
	attr->max_sge             = MAX_SGES;
	attr->max_cq              = MAX_CQS;
	attr->max_cqe             = MAX_CQ_SIZE;
	attr->max_mr              = MAX_MRS;
	attr->max_pd              = MAX_PDS;
	attr->max_qp_rd_atom      = MAX_IR>255 ? 255 : MAX_IR;
	attr->max_qp_init_rd_atom = MAX_OR>255 ? 255 : MAX_OR;
	attr->max_res_rd_atom     = MAX_IR>255 ? 255 : MAX_IR;
	attr->atomic_cap          = IB_ATOMIC_HCA;
	attr->sys_image_guid	  = ibdev->node_guid;

	return 0;
}

static int ibscif_query_port(struct ib_device *ibdev, u8 port,
			     struct ib_port_attr *attr)
{
	struct ibscif_dev *dev = to_dev(ibdev);

	memset(attr, 0, sizeof *attr);

	attr->lid	   = IBSCIF_NODE_ID_TO_LID(dev->node_id);
	attr->sm_lid	   = 1;
	attr->gid_tbl_len  = 1;
	attr->pkey_tbl_len = 1;
	attr->max_msg_sz   = MAX_MR_SIZE;
	attr->phys_state   = 5; /* LinkUp */
	attr->state	   = IB_PORT_ACTIVE;
	attr->max_mtu	   = IB_MTU_4096;
	attr->active_mtu   = IB_MTU_4096;
	attr->active_width = IB_WIDTH_4X;
	attr->active_speed = 4;
	attr->max_vl_num   = 1;
	attr->port_cap_flags = IB_PORT_SM_DISABLED;

	return 0;
}

static int ibscif_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
			     u16 *pkey)
{
	*pkey = 0xffff;	/* IB_DEFAULT_PKEY_FULL */
	return 0;
}

static int ibscif_query_gid(struct ib_device *ibdev, u8 port, int index,
			    union ib_gid *ibgid)
{
	struct ibscif_dev *dev = to_dev(ibdev);

	memcpy(ibgid, &dev->gid, sizeof(*ibgid));
	return 0;
}

static struct ib_ucontext *ibscif_alloc_ucontext(struct ib_device *ibdev,
						 struct ib_udata *udata)
{
	struct ib_ucontext *context = kzalloc(sizeof *context, GFP_KERNEL);
	return (!context) ? ERR_PTR(-ENOMEM) : context;
}

static int ibscif_dealloc_ucontext(struct ib_ucontext *context)
{
	kfree(context);
	return 0;
}

static void ibscif_generate_eui64(struct ibscif_dev *dev, u8 *eui64)
{
	memcpy(eui64, dev->netdev->dev_addr, 3);
	eui64[3] = 0xFF;
	eui64[4] = 0xFE;
	memcpy(eui64+5, dev->netdev->dev_addr+3, 3);
}

static int ibscif_register_device(struct ibscif_dev *dev)
{
	strncpy(dev->ibdev.node_desc, DRV_SIGNON, sizeof dev->ibdev.node_desc);
	ibscif_generate_eui64(dev, (u8 *)&dev->ibdev.node_guid);
	dev->ibdev.owner		= THIS_MODULE;
	dev->ibdev.uverbs_abi_ver	= UVERBS_ABI_VER;
	dev->ibdev.uverbs_cmd_mask	=
		(1ull << IB_USER_VERBS_CMD_GET_CONTEXT)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE)	|
		(1ull << IB_USER_VERBS_CMD_QUERY_PORT)		|
		(1ull << IB_USER_VERBS_CMD_ALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_DEALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_AH)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_AH)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_QP)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_QP)		|
		(1ull << IB_USER_VERBS_CMD_MODIFY_QP)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_QP)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL)	|
		(1ull << IB_USER_VERBS_CMD_CREATE_CQ)		|
		(1ull << IB_USER_VERBS_CMD_RESIZE_CQ)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_CQ)		|
		(1ull << IB_USER_VERBS_CMD_POLL_CQ)		|
		(1ull << IB_USER_VERBS_CMD_REQ_NOTIFY_CQ)	|
		(1ull << IB_USER_VERBS_CMD_REG_MR)		|
		(1ull << IB_USER_VERBS_CMD_DEREG_MR)		|
		(1ull << IB_USER_VERBS_CMD_POST_SEND)		|
		(1ull << IB_USER_VERBS_CMD_POST_RECV);
	dev->ibdev.node_type		= new_ib_type ? RDMA_NODE_MIC : RDMA_NODE_RNIC;
	dev->ibdev.phys_port_cnt	= 1;

	dev->ibdev.query_device		= ibscif_query_device;
	dev->ibdev.num_comp_vectors     = 1;
	dev->ibdev.query_port		= ibscif_query_port;
	dev->ibdev.query_pkey		= ibscif_query_pkey;
	dev->ibdev.query_gid		= ibscif_query_gid;
	dev->ibdev.alloc_ucontext	= ibscif_alloc_ucontext;
	dev->ibdev.dealloc_ucontext	= ibscif_dealloc_ucontext;
	dev->ibdev.alloc_pd		= ibscif_alloc_pd;
	dev->ibdev.dealloc_pd		= ibscif_dealloc_pd;
	dev->ibdev.create_ah		= ibscif_create_ah;
	dev->ibdev.destroy_ah		= ibscif_destroy_ah;
	dev->ibdev.create_qp		= ibscif_create_qp;
	dev->ibdev.query_qp		= ibscif_query_qp;
	dev->ibdev.modify_qp		= ibscif_modify_qp;
	dev->ibdev.destroy_qp		= ibscif_destroy_qp;
	dev->ibdev.create_cq		= ibscif_create_cq;
	dev->ibdev.resize_cq		= ibscif_resize_cq;
	dev->ibdev.destroy_cq		= ibscif_destroy_cq;
	dev->ibdev.poll_cq		= ibscif_poll_cq;
	dev->ibdev.req_notify_cq	= ibscif_arm_cq;
	dev->ibdev.get_dma_mr		= ibscif_get_dma_mr;
	dev->ibdev.reg_phys_mr		= ibscif_reg_phys_mr;
	dev->ibdev.reg_user_mr		= ibscif_reg_user_mr;
	dev->ibdev.dereg_mr		= ibscif_dereg_mr;
	dev->ibdev.post_send		= ibscif_post_send;
	dev->ibdev.post_recv		= ibscif_post_receive;
	dev->ibdev.dma_ops              = &ibscif_dma_mapping_ops;

	dev->ibdev.iwcm = kzalloc(sizeof(struct iw_cm_verbs), GFP_KERNEL);
	if (!dev->ibdev.iwcm)
		return -ENOMEM;

	dev->ibdev.iwcm->connect = ibscif_cm_connect;
	dev->ibdev.iwcm->accept = ibscif_cm_accept;
	dev->ibdev.iwcm->reject = ibscif_cm_reject;
	dev->ibdev.iwcm->create_listen = ibscif_cm_create_listen;
	dev->ibdev.iwcm->destroy_listen = ibscif_cm_destroy_listen;
	dev->ibdev.iwcm->add_ref = ibscif_cm_add_ref;
	dev->ibdev.iwcm->rem_ref = ibscif_cm_rem_ref;
	dev->ibdev.iwcm->get_qp = ibscif_cm_get_qp;

	return ib_register_device(&dev->ibdev, NULL);
}

static void ibscif_dev_release(struct device *dev)
{
	kfree(dev);
}

/*
 * Hold devlist_mutex during this call for synchronization as needed.
 * Upon return, dev is invalid.
 */
static void ibscif_remove_dev(struct ibscif_dev *dev)
{
	struct ibscif_conn *conn, *next;

	if (dev->ibdev.reg_state == IB_DEV_REGISTERED)
		ib_unregister_device(&dev->ibdev);

	WARN_ON(!list_empty(&dev->wq_list));

	mutex_lock(&devlist_mutex);
	list_del(&dev->entry);
	mutex_unlock(&devlist_mutex);

	ibscif_refresh_pollep_list();

	mutex_lock(&dev->mutex);
	list_for_each_entry_safe(conn, next, &dev->conn_list, entry) {
		scif_close(conn->ep);
		list_del(&conn->entry);
		kfree(conn);
	}
	mutex_unlock(&dev->mutex);

	if (dev->listen_ep)
		scif_close(dev->listen_ep);
	ibscif_procfs_remove_dev(dev);

	dev_put(dev->netdev);
	device_unregister(dev->ibdev.dma_device);
	ib_dealloc_device(&dev->ibdev);
}

static void ibscif_remove_one(struct net_device *netdev)
{
        struct ibscif_dev *dev, *next;

        list_for_each_entry_safe(dev, next, &devlist, entry) {
                if (netdev == dev->netdev) {
                        ibscif_remove_dev(dev);
                        break;
                }
        }
}

static int node_cnt;
static uint16_t node_ids[IBSCIF_MAX_DEVICES];
static uint16_t my_node_id;

static void ibscif_add_one(struct net_device *netdev)
{
	static int dev_cnt;
	static dma_addr_t dma_mask = -1;
	struct ibscif_dev *dev;
	int ret;

	dev = (struct ibscif_dev *)ib_alloc_device(sizeof *dev);
	if (!dev) {
		printk(KERN_ALERT PFX "%s: fail to allocate ib_device\n",
			__func__);
		return;
	}

	INIT_LIST_HEAD(&dev->conn_list);
	INIT_LIST_HEAD(&dev->mr_list);
	mutex_init(&dev->mr_list_mutex);
	mutex_init(&dev->mutex);
	spin_lock_init(&dev->atomic_op);
	INIT_LIST_HEAD(&dev->wq_list);
	atomic_set(&dev->available, 256);

	dev_hold(netdev);
	dev->netdev = netdev;

	/* use the MAC address of the netdev as the GID so that RDMA CM can
	 * find the ibdev from the IP address associated with the netdev.
	 */
	memcpy(&dev->gid, dev->netdev->dev_addr, ETH_ALEN);

	dev->ibdev.dma_device = kzalloc(sizeof *dev->ibdev.dma_device,
					GFP_KERNEL);
	if (!dev->ibdev.dma_device) {
		printk(KERN_ALERT PFX "%s: fail to allocate dma_device\n",
			__func__);
		goto out_free_ibdev;
	}

	snprintf(dev->name, IBSCIF_NAME_SIZE, "scif_dma_%d", dev_cnt);
	snprintf(dev->ibdev.name, IB_DEVICE_NAME_MAX, "scif%d", dev_cnt++);
	dev->ibdev.dma_device->release = ibscif_dev_release;
	dev->ibdev.dma_device->init_name = dev->name;
	dev->ibdev.dma_device->dma_mask = &dma_mask;
	ret = device_register(dev->ibdev.dma_device);
	if (ret) {
		printk(KERN_ALERT PFX
			"%s: fail to register dma_device, ret=%d\n",
			__func__, ret);
		kfree(dev->ibdev.dma_device);
		goto out_free_ibdev;
	}

	/* Notice: set up listen ep before inserting to devlist */

	dev->listen_ep = scif_open();
	if (!dev->listen_ep || IS_ERR(dev->listen_ep)) {
		printk(KERN_ALERT PFX "%s: scif_open returns %ld\n",
			__func__, PTR_ERR(dev->listen_ep));
		goto out_unreg_dmadev ;
	}

	ret = scif_get_node_ids( node_ids, IBSCIF_MAX_DEVICES, &my_node_id);
	if (ret < 0) {
		printk(KERN_ALERT PFX "%s: scif_get_nodeIDS returns %d\n",
			__func__, ret);
		goto out_close_ep;
	}

	node_cnt = ret;
	dev->node_id = my_node_id;
	printk(KERN_ALERT PFX "%s: my node_id is %d\n", __func__, dev->node_id);

	ret = scif_bind(dev->listen_ep, SCIF_OFED_PORT_0);
	if (ret < 0) {
		printk(KERN_ALERT PFX "%s: scif_bind returns %d, port=%d\n",
			__func__, ret, SCIF_OFED_PORT_0);
		goto out_close_ep;
	}

	ret = scif_listen(dev->listen_ep, IBSCIF_MAX_DEVICES);
	if (ret < 0) {
		printk(KERN_ALERT PFX "%s: scif_listen returns %d\n",
			__func__, ret);
		goto out_close_ep;
	}

	mutex_lock(&devlist_mutex);
	list_add_tail(&dev->entry, &devlist);
	mutex_unlock(&devlist_mutex);

	if (ibscif_register_device(dev))
		ibscif_remove_dev(dev);
	else
		ibscif_procfs_add_dev(dev);

	ibscif_refresh_pollep_list();

	return;

out_close_ep:
	scif_close(dev->listen_ep);

out_unreg_dmadev:
	device_unregister(dev->ibdev.dma_device);

out_free_ibdev:
	ib_dealloc_device(&dev->ibdev);
}

static int ibscif_notifier(struct notifier_block *nb, unsigned long event,
			   void *ptr)
{
	struct net_device *netdev = ((struct netdev_notifier_info *)ptr)->dev;

	if (strcmp(netdev->name, "mic0"))
		return NOTIFY_DONE;

	switch(event) {
	  case NETDEV_REGISTER:
		ibscif_add_one(netdev);
		ibscif_protocol_init_post();
		break;

	  case NETDEV_UNREGISTER:
		ibscif_remove_one(netdev);
		break;

	  default:
		/* we only care about the MAC address, ignore other
		 * notifications
		 */
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block ibscif_notifier_block = {
	.notifier_call = ibscif_notifier,
};

int ibscif_dev_init(void)
{
	int err = 0;

	ibscif_protocol_init_pre();

	err = register_netdevice_notifier(&ibscif_notifier_block);
	if (err)
		ibscif_protocol_cleanup();

	return err;
}

void ibscif_dev_cleanup(void)
{
	struct ibscif_dev *dev, *next;

	ibscif_protocol_cleanup();
	unregister_netdevice_notifier(&ibscif_notifier_block);
	list_for_each_entry_safe(dev, next, &devlist, entry)
		ibscif_remove_dev(dev);
}
