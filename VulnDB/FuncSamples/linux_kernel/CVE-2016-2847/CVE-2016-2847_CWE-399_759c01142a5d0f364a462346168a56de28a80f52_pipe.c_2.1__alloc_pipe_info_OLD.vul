struct pipe_inode_info *alloc_pipe_info(void)
{
	struct pipe_inode_info *pipe;

	pipe = kzalloc(sizeof(struct pipe_inode_info), GFP_KERNEL);
	if (pipe) {
		pipe->bufs = kzalloc(sizeof(struct pipe_buffer) * PIPE_DEF_BUFFERS, GFP_KERNEL);
		if (pipe->bufs) {
			init_waitqueue_head(&pipe->wait);
			pipe->r_counter = pipe->w_counter = 1;
			pipe->buffers = PIPE_DEF_BUFFERS;
			mutex_init(&pipe->mutex);
			return pipe;
		}
		kfree(pipe);
	}

	return NULL;
}
