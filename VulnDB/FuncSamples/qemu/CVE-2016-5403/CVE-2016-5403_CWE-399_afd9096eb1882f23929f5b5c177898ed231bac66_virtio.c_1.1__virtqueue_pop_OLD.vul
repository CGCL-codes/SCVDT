void *virtqueue_pop(VirtQueue *vq, size_t sz)
{
    unsigned int i, head, max;
    hwaddr desc_pa = vq->vring.desc;
    VirtIODevice *vdev = vq->vdev;
    VirtQueueElement *elem;
    unsigned out_num, in_num;
    hwaddr addr[VIRTQUEUE_MAX_SIZE];
    struct iovec iov[VIRTQUEUE_MAX_SIZE];
    VRingDesc desc;

    if (virtio_queue_empty(vq)) {
        return NULL;
    }
    /* Needed after virtio_queue_empty(), see comment in
     * virtqueue_num_heads(). */
    smp_rmb();

    /* When we start there are none of either input nor output. */
    out_num = in_num = 0;

    max = vq->vring.num;

    i = head = virtqueue_get_head(vq, vq->last_avail_idx++);
    if (virtio_vdev_has_feature(vdev, VIRTIO_RING_F_EVENT_IDX)) {
        vring_set_avail_event(vq, vq->last_avail_idx);
    }

    vring_desc_read(vdev, &desc, desc_pa, i);
    if (desc.flags & VRING_DESC_F_INDIRECT) {
        if (desc.len % sizeof(VRingDesc)) {
            error_report("Invalid size for indirect buffer table");
            exit(1);
        }

        /* loop over the indirect descriptor table */
        max = desc.len / sizeof(VRingDesc);
        desc_pa = desc.addr;
        i = 0;
        vring_desc_read(vdev, &desc, desc_pa, i);
    }

    /* Collect all the descriptors */
    do {
        if (desc.flags & VRING_DESC_F_WRITE) {
            virtqueue_map_desc(&in_num, addr + out_num, iov + out_num,
                               VIRTQUEUE_MAX_SIZE - out_num, true, desc.addr, desc.len);
        } else {
            if (in_num) {
                error_report("Incorrect order for descriptors");
                exit(1);
            }
            virtqueue_map_desc(&out_num, addr, iov,
                               VIRTQUEUE_MAX_SIZE, false, desc.addr, desc.len);
        }

        /* If we've got too many, that implies a descriptor loop. */
        if ((in_num + out_num) > max) {
            error_report("Looped descriptor");
            exit(1);
        }
    } while ((i = virtqueue_read_next_desc(vdev, &desc, desc_pa, max)) != max);

    /* Now copy what we have collected and mapped */
    elem = virtqueue_alloc_element(sz, out_num, in_num);
    elem->index = head;
    for (i = 0; i < out_num; i++) {
        elem->out_addr[i] = addr[i];
        elem->out_sg[i] = iov[i];
    }
    for (i = 0; i < in_num; i++) {
        elem->in_addr[i] = addr[out_num + i];
        elem->in_sg[i] = iov[out_num + i];
    }

    vq->inuse++;

    trace_virtqueue_pop(vq, elem, elem->in_num, elem->out_num);
    return elem;
}
