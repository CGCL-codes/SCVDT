static int rxrpc_preparse_xdr(struct key_preparsed_payload *prep)
{
	const __be32 *xdr = prep->data, *token;
	const char *cp;
	unsigned int len, tmp, loop, ntoken, toklen, sec_ix;
	size_t datalen = prep->datalen;
	int ret;

	_enter(",{%x,%x,%x,%x},%zu",
	       ntohl(xdr[0]), ntohl(xdr[1]), ntohl(xdr[2]), ntohl(xdr[3]),
	       prep->datalen);

	if (datalen > AFSTOKEN_LENGTH_MAX)
		goto not_xdr;

	/* XDR is an array of __be32's */
	if (datalen & 3)
		goto not_xdr;

	/* the flags should be 0 (the setpag bit must be handled by
	 * userspace) */
	if (ntohl(*xdr++) != 0)
		goto not_xdr;
	datalen -= 4;

	/* check the cell name */
	len = ntohl(*xdr++);
	if (len < 1 || len > AFSTOKEN_CELL_MAX)
		goto not_xdr;
	datalen -= 4;
	tmp = (len + 3) & ~3;
	if (tmp > datalen)
		goto not_xdr;

	cp = (const char *) xdr;
	for (loop = 0; loop < len; loop++)
		if (!isprint(cp[loop]))
			goto not_xdr;
	if (len < tmp)
		for (; loop < tmp; loop++)
			if (cp[loop])
				goto not_xdr;
	_debug("cellname: [%u/%u] '%*.*s'",
	       len, tmp, len, len, (const char *) xdr);
	datalen -= tmp;
	xdr += tmp >> 2;

	/* get the token count */
	if (datalen < 12)
		goto not_xdr;
	ntoken = ntohl(*xdr++);
	datalen -= 4;
	_debug("ntoken: %x", ntoken);
	if (ntoken < 1 || ntoken > AFSTOKEN_MAX)
		goto not_xdr;

	/* check each token wrapper */
	token = xdr;
	loop = ntoken;
	do {
		if (datalen < 8)
			goto not_xdr;
		toklen = ntohl(*xdr++);
		sec_ix = ntohl(*xdr);
		datalen -= 4;
		_debug("token: [%x/%zx] %x", toklen, datalen, sec_ix);
		if (toklen < 20 || toklen > datalen)
			goto not_xdr;
		datalen -= (toklen + 3) & ~3;
		xdr += (toklen + 3) >> 2;

	} while (--loop > 0);

	_debug("remainder: %zu", datalen);
	if (datalen != 0)
		goto not_xdr;

	/* okay: we're going to assume it's valid XDR format
	 * - we ignore the cellname, relying on the key to be correctly named
	 */
	do {
		xdr = token;
		toklen = ntohl(*xdr++);
		token = xdr + ((toklen + 3) >> 2);
		sec_ix = ntohl(*xdr++);
		toklen -= 4;

		_debug("TOKEN type=%u [%p-%p]", sec_ix, xdr, token);

		switch (sec_ix) {
		case RXRPC_SECURITY_RXKAD:
			ret = rxrpc_preparse_xdr_rxkad(prep, datalen, xdr, toklen);
			if (ret != 0)
				goto error;
			break;

		case RXRPC_SECURITY_RXK5:
			ret = rxrpc_preparse_xdr_rxk5(prep, datalen, xdr, toklen);
			if (ret != 0)
				goto error;
			break;

		default:
			ret = -EPROTONOSUPPORT;
			goto error;
		}

	} while (--ntoken > 0);

	_leave(" = 0");
	return 0;

not_xdr:
	_leave(" = -EPROTO");
	return -EPROTO;
error:
	_leave(" = %d", ret);
	return ret;
}
