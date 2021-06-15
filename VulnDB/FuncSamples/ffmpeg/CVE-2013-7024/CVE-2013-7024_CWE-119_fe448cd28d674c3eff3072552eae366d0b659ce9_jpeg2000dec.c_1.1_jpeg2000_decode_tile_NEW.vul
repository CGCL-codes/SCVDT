static int jpeg2000_decode_tile(Jpeg2000DecoderContext *s, Jpeg2000Tile *tile,
                                AVFrame *picture)
{
    int compno, reslevelno, bandno;
    int x, y;

    uint8_t *line;
    Jpeg2000T1Context t1;

    /* Loop on tile components */
    for (compno = 0; compno < s->ncomponents; compno++) {
        Jpeg2000Component *comp     = tile->comp + compno;
        Jpeg2000CodingStyle *codsty = tile->codsty + compno;

        /* Loop on resolution levels */
        for (reslevelno = 0; reslevelno < codsty->nreslevels2decode; reslevelno++) {
            Jpeg2000ResLevel *rlevel = comp->reslevel + reslevelno;
            /* Loop on bands */
            for (bandno = 0; bandno < rlevel->nbands; bandno++) {
                int nb_precincts, precno;
                Jpeg2000Band *band = rlevel->band + bandno;
                int cblkno = 0, bandpos;

                bandpos = bandno + (reslevelno > 0);

                if (band->coord[0][0] == band->coord[0][1] ||
                    band->coord[1][0] == band->coord[1][1])
                    continue;

                nb_precincts = rlevel->num_precincts_x * rlevel->num_precincts_y;
                /* Loop on precincts */
                for (precno = 0; precno < nb_precincts; precno++) {
                    Jpeg2000Prec *prec = band->prec + precno;

                    /* Loop on codeblocks */
                    for (cblkno = 0; cblkno < prec->nb_codeblocks_width * prec->nb_codeblocks_height; cblkno++) {
                        int x, y;
                        Jpeg2000Cblk *cblk = prec->cblk + cblkno;
                        decode_cblk(s, codsty, &t1, cblk,
                                    cblk->coord[0][1] - cblk->coord[0][0],
                                    cblk->coord[1][1] - cblk->coord[1][0],
                                    bandpos);

                        x = cblk->coord[0][0];
                        y = cblk->coord[1][0];

                        if (codsty->transform == FF_DWT97)
                            dequantization_float(x, y, cblk, comp, &t1, band);
                        else
                            dequantization_int(x, y, cblk, comp, &t1, band);
                   } /* end cblk */
                } /*end prec */
            } /* end band */
        } /* end reslevel */

        /* inverse DWT */
        ff_dwt_decode(&comp->dwt, codsty->transform == FF_DWT97 ? (void*)comp->f_data : (void*)comp->i_data);
    } /*end comp */

    /* inverse MCT transformation */
    if (tile->codsty[0].mct)
        mct_decode(s, tile);

    if (s->cdef[0] < 0) {
        for (x = 0; x < s->ncomponents; x++)
            s->cdef[x] = x + 1;
        if ((s->ncomponents & 1) == 0)
            s->cdef[s->ncomponents-1] = 0;
    }

    if (s->precision <= 8) {
        for (compno = 0; compno < s->ncomponents; compno++) {
            Jpeg2000Component *comp = tile->comp + compno;
            Jpeg2000CodingStyle *codsty = tile->codsty + compno;
            float *datap = comp->f_data;
            int32_t *i_datap = comp->i_data;
            int cbps = s->cbps[compno];
            int w = tile->comp[compno].coord[0][1] - s->image_offset_x;
            int planar = !!picture->data[2];
            int pixelsize = planar ? 1 : s->ncomponents;
            int plane = 0;

            if (planar)
                plane = s->cdef[compno] ? s->cdef[compno]-1 : (s->ncomponents-1);


            y    = tile->comp[compno].coord[1][0] - s->image_offset_y;
            line = picture->data[plane] + y / s->cdy[compno] * picture->linesize[plane];
            for (; y < tile->comp[compno].coord[1][1] - s->image_offset_y; y += s->cdy[compno]) {
                uint8_t *dst;

                x   = tile->comp[compno].coord[0][0] - s->image_offset_x;
                dst = line + x / s->cdx[compno] * pixelsize + compno*!planar;

                if (codsty->transform == FF_DWT97) {
                    for (; x < w; x += s->cdx[compno]) {
                        int val = lrintf(*datap) + (1 << (cbps - 1));
                        /* DC level shift and clip see ISO 15444-1:2002 G.1.2 */
                        val = av_clip(val, 0, (1 << cbps) - 1);
                        *dst = val << (8 - cbps);
                        datap++;
                        dst += pixelsize;
                    }
                } else {
                    for (; x < w; x += s->cdx[compno]) {
                        int val = *i_datap + (1 << (cbps - 1));
                        /* DC level shift and clip see ISO 15444-1:2002 G.1.2 */
                        val = av_clip(val, 0, (1 << cbps) - 1);
                        *dst = val << (8 - cbps);
                        i_datap++;
                        dst += pixelsize;
                    }
                }
                line += picture->linesize[plane];
            }
        }
    } else {
        for (compno = 0; compno < s->ncomponents; compno++) {
            Jpeg2000Component *comp = tile->comp + compno;
            Jpeg2000CodingStyle *codsty = tile->codsty + compno;
            float *datap = comp->f_data;
            int32_t *i_datap = comp->i_data;
            uint16_t *linel;
            int cbps = s->cbps[compno];
            int w = tile->comp[compno].coord[0][1] - s->image_offset_x;
            int planar = !!picture->data[2];
            int pixelsize = planar ? 1 : s->ncomponents;
            int plane = 0;

            if (planar)
                plane = s->cdef[compno] ? s->cdef[compno]-1 : (s->ncomponents-1);

            y     = tile->comp[compno].coord[1][0] - s->image_offset_y;
            linel = (uint16_t *)picture->data[plane] + y / s->cdy[compno] * (picture->linesize[plane] >> 1);
            for (; y < tile->comp[compno].coord[1][1] - s->image_offset_y; y += s->cdy[compno]) {
                uint16_t *dst;

                x   = tile->comp[compno].coord[0][0] - s->image_offset_x;
                dst = linel + (x / s->cdx[compno] * pixelsize + compno*!planar);
                if (codsty->transform == FF_DWT97) {
                    for (; x < w; x += s-> cdx[compno]) {
                        int  val = lrintf(*datap) + (1 << (cbps - 1));
                        /* DC level shift and clip see ISO 15444-1:2002 G.1.2 */
                        val = av_clip(val, 0, (1 << cbps) - 1);
                        /* align 12 bit values in little-endian mode */
                        *dst = val << (16 - cbps);
                        datap++;
                        dst += pixelsize;
                    }
                } else {
                    for (; x < w; x += s-> cdx[compno]) {
                        int val = *i_datap + (1 << (cbps - 1));
                        /* DC level shift and clip see ISO 15444-1:2002 G.1.2 */
                        val = av_clip(val, 0, (1 << cbps) - 1);
                        /* align 12 bit values in little-endian mode */
                        *dst = val << (16 - cbps);
                        i_datap++;
                        dst += pixelsize;
                    }
                }
                linel += picture->linesize[plane] >> 1;
            }
        }
    }

    return 0;
}
