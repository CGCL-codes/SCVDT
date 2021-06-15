static noinline_for_stack int
ccp_run_sha_cmd(struct ccp_cmd_queue *cmd_q, struct ccp_cmd *cmd)
{
	struct ccp_sha_engine *sha = &cmd->u.sha;
	struct ccp_dm_workarea ctx;
	struct ccp_data src;
	struct ccp_op op;
	unsigned int ioffset, ooffset;
	unsigned int digest_size;
	int sb_count;
	const void *init;
	u64 block_size;
	int ctx_size;
	int ret;

	switch (sha->type) {
	case CCP_SHA_TYPE_1:
		if (sha->ctx_len < SHA1_DIGEST_SIZE)
			return -EINVAL;
		block_size = SHA1_BLOCK_SIZE;
		break;
	case CCP_SHA_TYPE_224:
		if (sha->ctx_len < SHA224_DIGEST_SIZE)
			return -EINVAL;
		block_size = SHA224_BLOCK_SIZE;
		break;
	case CCP_SHA_TYPE_256:
		if (sha->ctx_len < SHA256_DIGEST_SIZE)
			return -EINVAL;
		block_size = SHA256_BLOCK_SIZE;
		break;
	case CCP_SHA_TYPE_384:
		if (cmd_q->ccp->vdata->version < CCP_VERSION(4, 0)
		    || sha->ctx_len < SHA384_DIGEST_SIZE)
			return -EINVAL;
		block_size = SHA384_BLOCK_SIZE;
		break;
	case CCP_SHA_TYPE_512:
		if (cmd_q->ccp->vdata->version < CCP_VERSION(4, 0)
		    || sha->ctx_len < SHA512_DIGEST_SIZE)
			return -EINVAL;
		block_size = SHA512_BLOCK_SIZE;
		break;
	default:
		return -EINVAL;
	}

	if (!sha->ctx)
		return -EINVAL;

	if (!sha->final && (sha->src_len & (block_size - 1)))
		return -EINVAL;

	/* The version 3 device can't handle zero-length input */
	if (cmd_q->ccp->vdata->version == CCP_VERSION(3, 0)) {

		if (!sha->src_len) {
			unsigned int digest_len;
			const u8 *sha_zero;

			/* Not final, just return */
			if (!sha->final)
				return 0;

			/* CCP can't do a zero length sha operation so the
			 * caller must buffer the data.
			 */
			if (sha->msg_bits)
				return -EINVAL;

			/* The CCP cannot perform zero-length sha operations
			 * so the caller is required to buffer data for the
			 * final operation. However, a sha operation for a
			 * message with a total length of zero is valid so
			 * known values are required to supply the result.
			 */
			switch (sha->type) {
			case CCP_SHA_TYPE_1:
				sha_zero = sha1_zero_message_hash;
				digest_len = SHA1_DIGEST_SIZE;
				break;
			case CCP_SHA_TYPE_224:
				sha_zero = sha224_zero_message_hash;
				digest_len = SHA224_DIGEST_SIZE;
				break;
			case CCP_SHA_TYPE_256:
				sha_zero = sha256_zero_message_hash;
				digest_len = SHA256_DIGEST_SIZE;
				break;
			default:
				return -EINVAL;
			}

			scatterwalk_map_and_copy((void *)sha_zero, sha->ctx, 0,
						 digest_len, 1);

			return 0;
		}
	}

	/* Set variables used throughout */
	switch (sha->type) {
	case CCP_SHA_TYPE_1:
		digest_size = SHA1_DIGEST_SIZE;
		init = (void *) ccp_sha1_init;
		ctx_size = SHA1_DIGEST_SIZE;
		sb_count = 1;
		if (cmd_q->ccp->vdata->version != CCP_VERSION(3, 0))
			ooffset = ioffset = CCP_SB_BYTES - SHA1_DIGEST_SIZE;
		else
			ooffset = ioffset = 0;
		break;
	case CCP_SHA_TYPE_224:
		digest_size = SHA224_DIGEST_SIZE;
		init = (void *) ccp_sha224_init;
		ctx_size = SHA256_DIGEST_SIZE;
		sb_count = 1;
		ioffset = 0;
		if (cmd_q->ccp->vdata->version != CCP_VERSION(3, 0))
			ooffset = CCP_SB_BYTES - SHA224_DIGEST_SIZE;
		else
			ooffset = 0;
		break;
	case CCP_SHA_TYPE_256:
		digest_size = SHA256_DIGEST_SIZE;
		init = (void *) ccp_sha256_init;
		ctx_size = SHA256_DIGEST_SIZE;
		sb_count = 1;
		ooffset = ioffset = 0;
		break;
	case CCP_SHA_TYPE_384:
		digest_size = SHA384_DIGEST_SIZE;
		init = (void *) ccp_sha384_init;
		ctx_size = SHA512_DIGEST_SIZE;
		sb_count = 2;
		ioffset = 0;
		ooffset = 2 * CCP_SB_BYTES - SHA384_DIGEST_SIZE;
		break;
	case CCP_SHA_TYPE_512:
		digest_size = SHA512_DIGEST_SIZE;
		init = (void *) ccp_sha512_init;
		ctx_size = SHA512_DIGEST_SIZE;
		sb_count = 2;
		ooffset = ioffset = 0;
		break;
	default:
		ret = -EINVAL;
		goto e_data;
	}

	/* For zero-length plaintext the src pointer is ignored;
	 * otherwise both parts must be valid
	 */
	if (sha->src_len && !sha->src)
		return -EINVAL;

	memset(&op, 0, sizeof(op));
	op.cmd_q = cmd_q;
	op.jobid = CCP_NEW_JOBID(cmd_q->ccp);
	op.sb_ctx = cmd_q->sb_ctx; /* Pre-allocated */
	op.u.sha.type = sha->type;
	op.u.sha.msg_bits = sha->msg_bits;

	/* For SHA1/224/256 the context fits in a single (32-byte) SB entry;
	 * SHA384/512 require 2 adjacent SB slots, with the right half in the
	 * first slot, and the left half in the second. Each portion must then
	 * be in little endian format: use the 256-bit byte swap option.
	 */
	ret = ccp_init_dm_workarea(&ctx, cmd_q, sb_count * CCP_SB_BYTES,
				   DMA_BIDIRECTIONAL);
	if (ret)
		return ret;
	if (sha->first) {
		switch (sha->type) {
		case CCP_SHA_TYPE_1:
		case CCP_SHA_TYPE_224:
		case CCP_SHA_TYPE_256:
			memcpy(ctx.address + ioffset, init, ctx_size);
			break;
		case CCP_SHA_TYPE_384:
		case CCP_SHA_TYPE_512:
			memcpy(ctx.address + ctx_size / 2, init,
			       ctx_size / 2);
			memcpy(ctx.address, init + ctx_size / 2,
			       ctx_size / 2);
			break;
		default:
			ret = -EINVAL;
			goto e_ctx;
		}
	} else {
		/* Restore the context */
		ret = ccp_set_dm_area(&ctx, 0, sha->ctx, 0,
				      sb_count * CCP_SB_BYTES);
		if (ret)
			goto e_ctx;
	}

	ret = ccp_copy_to_sb(cmd_q, &ctx, op.jobid, op.sb_ctx,
			     CCP_PASSTHRU_BYTESWAP_256BIT);
	if (ret) {
		cmd->engine_error = cmd_q->cmd_error;
		goto e_ctx;
	}

	if (sha->src) {
		/* Send data to the CCP SHA engine; block_size is set above */
		ret = ccp_init_data(&src, cmd_q, sha->src, sha->src_len,
				    block_size, DMA_TO_DEVICE);
		if (ret)
			goto e_ctx;

		while (src.sg_wa.bytes_left) {
			ccp_prepare_data(&src, NULL, &op, block_size, false);
			if (sha->final && !src.sg_wa.bytes_left)
				op.eom = 1;

			ret = cmd_q->ccp->vdata->perform->sha(&op);
			if (ret) {
				cmd->engine_error = cmd_q->cmd_error;
				goto e_data;
			}

			ccp_process_data(&src, NULL, &op);
		}
	} else {
		op.eom = 1;
		ret = cmd_q->ccp->vdata->perform->sha(&op);
		if (ret) {
			cmd->engine_error = cmd_q->cmd_error;
			goto e_data;
		}
	}

	/* Retrieve the SHA context - convert from LE to BE using
	 * 32-byte (256-bit) byteswapping to BE
	 */
	ret = ccp_copy_from_sb(cmd_q, &ctx, op.jobid, op.sb_ctx,
			       CCP_PASSTHRU_BYTESWAP_256BIT);
	if (ret) {
		cmd->engine_error = cmd_q->cmd_error;
		goto e_data;
	}

	if (sha->final) {
		/* Finishing up, so get the digest */
		switch (sha->type) {
		case CCP_SHA_TYPE_1:
		case CCP_SHA_TYPE_224:
		case CCP_SHA_TYPE_256:
			ccp_get_dm_area(&ctx, ooffset,
					sha->ctx, 0,
					digest_size);
			break;
		case CCP_SHA_TYPE_384:
		case CCP_SHA_TYPE_512:
			ccp_get_dm_area(&ctx, 0,
					sha->ctx, LSB_ITEM_SIZE - ooffset,
					LSB_ITEM_SIZE);
			ccp_get_dm_area(&ctx, LSB_ITEM_SIZE + ooffset,
					sha->ctx, 0,
					LSB_ITEM_SIZE - ooffset);
			break;
		default:
			ret = -EINVAL;
			goto e_ctx;
		}
	} else {
		/* Stash the context */
		ccp_get_dm_area(&ctx, 0, sha->ctx, 0,
				sb_count * CCP_SB_BYTES);
	}

	if (sha->final && sha->opad) {
		/* HMAC operation, recursively perform final SHA */
		struct ccp_cmd hmac_cmd;
		struct scatterlist sg;
		u8 *hmac_buf;

		if (sha->opad_len != block_size) {
			ret = -EINVAL;
			goto e_data;
		}

		hmac_buf = kmalloc(block_size + digest_size, GFP_KERNEL);
		if (!hmac_buf) {
			ret = -ENOMEM;
			goto e_data;
		}
		sg_init_one(&sg, hmac_buf, block_size + digest_size);

		scatterwalk_map_and_copy(hmac_buf, sha->opad, 0, block_size, 0);
		switch (sha->type) {
		case CCP_SHA_TYPE_1:
		case CCP_SHA_TYPE_224:
		case CCP_SHA_TYPE_256:
			memcpy(hmac_buf + block_size,
			       ctx.address + ooffset,
			       digest_size);
			break;
		case CCP_SHA_TYPE_384:
		case CCP_SHA_TYPE_512:
			memcpy(hmac_buf + block_size,
			       ctx.address + LSB_ITEM_SIZE + ooffset,
			       LSB_ITEM_SIZE);
			memcpy(hmac_buf + block_size +
			       (LSB_ITEM_SIZE - ooffset),
			       ctx.address,
			       LSB_ITEM_SIZE);
			break;
		default:
			ret = -EINVAL;
			goto e_ctx;
		}

		memset(&hmac_cmd, 0, sizeof(hmac_cmd));
		hmac_cmd.engine = CCP_ENGINE_SHA;
		hmac_cmd.u.sha.type = sha->type;
		hmac_cmd.u.sha.ctx = sha->ctx;
		hmac_cmd.u.sha.ctx_len = sha->ctx_len;
		hmac_cmd.u.sha.src = &sg;
		hmac_cmd.u.sha.src_len = block_size + digest_size;
		hmac_cmd.u.sha.opad = NULL;
		hmac_cmd.u.sha.opad_len = 0;
		hmac_cmd.u.sha.first = 1;
		hmac_cmd.u.sha.final = 1;
		hmac_cmd.u.sha.msg_bits = (block_size + digest_size) << 3;

		ret = ccp_run_sha_cmd(cmd_q, &hmac_cmd);
		if (ret)
			cmd->engine_error = hmac_cmd.engine_error;

		kfree(hmac_buf);
	}

e_data:
	if (sha->src)
		ccp_free_data(&src, cmd_q);

e_ctx:
	ccp_dm_free(&ctx);

	return ret;
}
