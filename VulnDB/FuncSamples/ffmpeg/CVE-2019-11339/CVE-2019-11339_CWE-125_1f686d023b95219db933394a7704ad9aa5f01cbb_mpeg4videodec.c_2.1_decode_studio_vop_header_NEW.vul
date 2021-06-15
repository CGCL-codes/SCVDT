static int decode_studio_vop_header(Mpeg4DecContext *ctx, GetBitContext *gb)
{
    MpegEncContext *s = &ctx->m;

    if (get_bits_left(gb) <= 32)
        return 0;

    s->partitioned_frame = 0;
    s->interlaced_dct = 0;
    s->decode_mb = mpeg4_decode_studio_mb;

    decode_smpte_tc(ctx, gb);

    skip_bits(gb, 10); /* temporal_reference */
    skip_bits(gb, 2); /* vop_structure */
    s->pict_type = get_bits(gb, 2) + AV_PICTURE_TYPE_I; /* vop_coding_type */
    if (get_bits1(gb)) { /* vop_coded */
        skip_bits1(gb); /* top_field_first */
        skip_bits1(gb); /* repeat_first_field */
        s->progressive_frame = get_bits1(gb) ^ 1; /* progressive_frame */
    }

    if (s->pict_type == AV_PICTURE_TYPE_I) {
        if (get_bits1(gb))
            reset_studio_dc_predictors(s);
    }

    if (ctx->shape != BIN_ONLY_SHAPE) {
        s->alternate_scan = get_bits1(gb);
        s->frame_pred_frame_dct = get_bits1(gb);
        s->dct_precision = get_bits(gb, 2);
        s->intra_dc_precision = get_bits(gb, 2);
        s->q_scale_type = get_bits1(gb);
    }

    if (s->alternate_scan) {
        ff_init_scantable(s->idsp.idct_permutation, &s->inter_scantable,   ff_alternate_vertical_scan);
        ff_init_scantable(s->idsp.idct_permutation, &s->intra_scantable,   ff_alternate_vertical_scan);
        ff_init_scantable(s->idsp.idct_permutation, &s->intra_h_scantable, ff_alternate_vertical_scan);
        ff_init_scantable(s->idsp.idct_permutation, &s->intra_v_scantable, ff_alternate_vertical_scan);
    } else {
        ff_init_scantable(s->idsp.idct_permutation, &s->inter_scantable,   ff_zigzag_direct);
        ff_init_scantable(s->idsp.idct_permutation, &s->intra_scantable,   ff_zigzag_direct);
        ff_init_scantable(s->idsp.idct_permutation, &s->intra_h_scantable, ff_alternate_horizontal_scan);
        ff_init_scantable(s->idsp.idct_permutation, &s->intra_v_scantable, ff_alternate_vertical_scan);
    }

    mpeg4_load_default_matrices(s);

    next_start_code_studio(gb);
    extension_and_user_data(s, gb, 4);

    return 0;
}
