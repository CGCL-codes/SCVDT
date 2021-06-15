static int ceph_x_decrypt(struct ceph_crypto_key *secret,
			  void **p, void *end, void *obuf, size_t olen)
{
	struct ceph_x_encrypt_header head;
	size_t head_len = sizeof(head);
	int len, ret;

	len = ceph_decode_32(p);
	if (*p + len > end)
		return -EINVAL;

	dout("ceph_x_decrypt len %d\n", len);
	ret = ceph_decrypt2(secret, &head, &head_len, obuf, &olen,
			    *p, len);
	if (ret)
		return ret;
	if (head.struct_v != 1 || le64_to_cpu(head.magic) != CEPHX_ENC_MAGIC)
		return -EPERM;
	*p += len;
	return olen;
}
