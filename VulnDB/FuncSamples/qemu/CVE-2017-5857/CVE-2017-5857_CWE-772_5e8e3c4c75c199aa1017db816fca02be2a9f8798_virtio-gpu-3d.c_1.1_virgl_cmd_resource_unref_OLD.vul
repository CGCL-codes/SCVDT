static void virgl_cmd_resource_unref(VirtIOGPU *g,
                                     struct virtio_gpu_ctrl_command *cmd)
{
    struct virtio_gpu_resource_unref unref;

    VIRTIO_GPU_FILL_CMD(unref);
    trace_virtio_gpu_cmd_res_unref(unref.resource_id);

    virgl_renderer_resource_unref(unref.resource_id);
}
