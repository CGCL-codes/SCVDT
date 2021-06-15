uint32_t virtio_config_readl(VirtIODevice *vdev, uint32_t addr)
{
    VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
    uint32_t val;

    k->get_config(vdev, vdev->config);

    if (addr > (vdev->config_len - sizeof(val)))
        return (uint32_t)-1;

    val = ldl_p(vdev->config + addr);
    return val;
}
