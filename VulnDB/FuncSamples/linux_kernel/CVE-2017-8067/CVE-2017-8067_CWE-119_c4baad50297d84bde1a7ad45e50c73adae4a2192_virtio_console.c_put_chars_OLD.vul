static int put_chars(u32 vtermno, const char *buf, int count)
{
	struct port *port;
	struct scatterlist sg[1];

	if (unlikely(early_put_chars))
		return early_put_chars(vtermno, buf, count);

	port = find_port_by_vtermno(vtermno);
	if (!port)
		return -EPIPE;

	sg_init_one(sg, buf, count);
	return __send_to_port(port, sg, 1, count, (void *)buf, false);
}
