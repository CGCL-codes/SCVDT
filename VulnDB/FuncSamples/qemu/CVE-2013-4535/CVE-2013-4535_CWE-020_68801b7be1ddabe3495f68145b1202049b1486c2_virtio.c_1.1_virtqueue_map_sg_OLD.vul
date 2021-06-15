void virtqueue_map_sg(struct iovec *sg, hwaddr *addr,
    size_t num_sg, int is_write)
{
    unsigned int i;
    hwaddr len;

    for (i = 0; i < num_sg; i++) {
        len = sg[i].iov_len;
        sg[i].iov_base = cpu_physical_memory_map(addr[i], &len, is_write);
        if (sg[i].iov_base == NULL || len != sg[i].iov_len) {
            error_report("virtio: trying to map MMIO memory");
            exit(1);
        }
    }
}
