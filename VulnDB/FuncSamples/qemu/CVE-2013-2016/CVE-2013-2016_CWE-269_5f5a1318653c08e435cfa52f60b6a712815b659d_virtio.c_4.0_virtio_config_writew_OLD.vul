void virtio_config_writew(VirtIODevice *vdev, uint32_t addr, uint32_t data)
{
    VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
    uint16_t val = data;

    if (addr > (vdev->config_len - sizeof(val)))
        return;

    stw_p(vdev->config + addr, val);

    if (k->set_config) {
        k->set_config(vdev, vdev->config);
    }
}
