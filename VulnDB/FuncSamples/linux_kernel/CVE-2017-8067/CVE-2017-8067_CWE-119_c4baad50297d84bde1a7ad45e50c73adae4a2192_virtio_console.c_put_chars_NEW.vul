static int put_chars(u32 vtermno, const char *buf, int count)
{
	struct port *port;
	struct scatterlist sg[1];
	void *data;
	int ret;

	if (unlikely(early_put_chars))
		return early_put_chars(vtermno, buf, count);

	port = find_port_by_vtermno(vtermno);
	if (!port)
		return -EPIPE;

	data = kmemdup(buf, count, GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	sg_init_one(sg, data, count);
	ret = __send_to_port(port, sg, 1, count, data, false);
	kfree(data);
	return ret;
}
