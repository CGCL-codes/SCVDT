bool generic_pipe_buf_get(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
{
	return try_get_page(buf->page);
}
