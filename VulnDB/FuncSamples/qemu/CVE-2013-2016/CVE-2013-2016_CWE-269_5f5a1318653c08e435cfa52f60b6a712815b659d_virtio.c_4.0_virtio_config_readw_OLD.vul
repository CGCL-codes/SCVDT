uint32_t virtio_config_readw(VirtIODevice *vdev, uint32_t addr)
{
    VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
    uint16_t val;

    k->get_config(vdev, vdev->config);

    if (addr > (vdev->config_len - sizeof(val)))
        return (uint32_t)-1;

    val = lduw_p(vdev->config + addr);
    return val;
}
