void virtio_queue_set_addr(VirtIODevice *vdev, int n, hwaddr addr)
{
    vdev->vq[n].vring.desc = addr;
    virtio_queue_update_rings(vdev, n);
}
