static int tiff_decode_tag(TiffContext *s, AVFrame *frame)
{
    unsigned tag, type, count, off, value = 0, value2 = 0;
    int i, start;
    int pos;
    int ret;
    double *dp;

    ret = ff_tread_tag(&s->gb, s->le, &tag, &type, &count, &start);
    if (ret < 0) {
        goto end;
    }

    off = bytestream2_tell(&s->gb);
    if (count == 1) {
        switch (type) {
        case TIFF_BYTE:
        case TIFF_SHORT:
        case TIFF_LONG:
            value = ff_tget(&s->gb, type, s->le);
            break;
        case TIFF_RATIONAL:
            value  = ff_tget(&s->gb, TIFF_LONG, s->le);
            value2 = ff_tget(&s->gb, TIFF_LONG, s->le);
            break;
        case TIFF_STRING:
            if (count <= 4) {
                break;
            }
        default:
            value = UINT_MAX;
        }
    }

    switch (tag) {
    case TIFF_WIDTH:
        s->width = value;
        break;
    case TIFF_HEIGHT:
        s->height = value;
        break;
    case TIFF_BPP:
        if (count > 4U) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "This format is not supported (bpp=%d, %d components)\n",
                   value, count);
            return AVERROR_INVALIDDATA;
        }
        s->bppcount = count;
        if (count == 1)
            s->bpp = value;
        else {
            switch (type) {
            case TIFF_BYTE:
            case TIFF_SHORT:
            case TIFF_LONG:
                s->bpp = 0;
                if (bytestream2_get_bytes_left(&s->gb) < type_sizes[type] * count)
                    return AVERROR_INVALIDDATA;
                for (i = 0; i < count; i++)
                    s->bpp += ff_tget(&s->gb, type, s->le);
                break;
            default:
                s->bpp = -1;
            }
        }
        break;
    case TIFF_SAMPLES_PER_PIXEL:
        if (count != 1) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "Samples per pixel requires a single value, many provided\n");
            return AVERROR_INVALIDDATA;
        }
        if (value > 4U) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "Samples per pixel %d is too large\n", value);
            return AVERROR_INVALIDDATA;
        }
        if (s->bppcount == 1)
            s->bpp *= value;
        s->bppcount = value;
        break;
    case TIFF_COMPR:
        s->compr     = value;
        s->predictor = 0;
        switch (s->compr) {
        case TIFF_RAW:
        case TIFF_PACKBITS:
        case TIFF_LZW:
        case TIFF_CCITT_RLE:
            break;
        case TIFF_G3:
        case TIFF_G4:
            s->fax_opts = 0;
            break;
        case TIFF_DEFLATE:
        case TIFF_ADOBE_DEFLATE:
#if CONFIG_ZLIB
            break;
#else
            av_log(s->avctx, AV_LOG_ERROR, "Deflate: ZLib not compiled in\n");
            return AVERROR(ENOSYS);
#endif
        case TIFF_JPEG:
        case TIFF_NEWJPEG:
            avpriv_report_missing_feature(s->avctx, "JPEG compression");
            return AVERROR_PATCHWELCOME;
        case TIFF_LZMA:
#if CONFIG_LZMA
            break;
#else
            av_log(s->avctx, AV_LOG_ERROR, "LZMA not compiled in\n");
            return AVERROR(ENOSYS);
#endif
        default:
            av_log(s->avctx, AV_LOG_ERROR, "Unknown compression method %i\n",
                   s->compr);
            return AVERROR_INVALIDDATA;
        }
        break;
    case TIFF_ROWSPERSTRIP:
        if (!value || (type == TIFF_LONG && value == UINT_MAX))
            value = s->height;
        s->rps = FFMIN(value, s->height);
        break;
    case TIFF_STRIP_OFFS:
        if (count == 1) {
            s->strippos = 0;
            s->stripoff = value;
        } else
            s->strippos = off;
        s->strips = count;
        if (s->strips == 1)
            s->rps = s->height;
        s->sot = type;
        break;
    case TIFF_STRIP_SIZE:
        if (count == 1) {
            s->stripsizesoff = 0;
            s->stripsize     = value;
            s->strips        = 1;
        } else {
            s->stripsizesoff = off;
        }
        s->strips = count;
        s->sstype = type;
        break;
    case TIFF_XRES:
    case TIFF_YRES:
        set_sar(s, tag, value, value2);
        break;
    case TIFF_TILE_BYTE_COUNTS:
    case TIFF_TILE_LENGTH:
    case TIFF_TILE_OFFSETS:
    case TIFF_TILE_WIDTH:
        av_log(s->avctx, AV_LOG_ERROR, "Tiled images are not supported\n");
        return AVERROR_PATCHWELCOME;
        break;
    case TIFF_PREDICTOR:
        s->predictor = value;
        break;
    case TIFF_PHOTOMETRIC:
        switch (value) {
        case TIFF_PHOTOMETRIC_WHITE_IS_ZERO:
        case TIFF_PHOTOMETRIC_BLACK_IS_ZERO:
        case TIFF_PHOTOMETRIC_RGB:
        case TIFF_PHOTOMETRIC_PALETTE:
        case TIFF_PHOTOMETRIC_YCBCR:
            s->photometric = value;
            break;
        case TIFF_PHOTOMETRIC_ALPHA_MASK:
        case TIFF_PHOTOMETRIC_SEPARATED:
        case TIFF_PHOTOMETRIC_CIE_LAB:
        case TIFF_PHOTOMETRIC_ICC_LAB:
        case TIFF_PHOTOMETRIC_ITU_LAB:
        case TIFF_PHOTOMETRIC_CFA:
        case TIFF_PHOTOMETRIC_LOG_L:
        case TIFF_PHOTOMETRIC_LOG_LUV:
        case TIFF_PHOTOMETRIC_LINEAR_RAW:
            avpriv_report_missing_feature(s->avctx,
                                          "PhotometricInterpretation 0x%04X",
                                          value);
            return AVERROR_PATCHWELCOME;
        default:
            av_log(s->avctx, AV_LOG_ERROR, "PhotometricInterpretation %u is "
                   "unknown\n", value);
            return AVERROR_INVALIDDATA;
        }
        break;
    case TIFF_FILL_ORDER:
        if (value < 1 || value > 2) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "Unknown FillOrder value %d, trying default one\n", value);
            value = 1;
        }
        s->fill_order = value - 1;
        break;
    case TIFF_PAL: {
        GetByteContext pal_gb[3];
        off = type_sizes[type];
        if (count / 3 > 256 ||
            bytestream2_get_bytes_left(&s->gb) < count / 3 * off * 3)
            return AVERROR_INVALIDDATA;

        pal_gb[0] = pal_gb[1] = pal_gb[2] = s->gb;
        bytestream2_skip(&pal_gb[1], count / 3 * off);
        bytestream2_skip(&pal_gb[2], count / 3 * off * 2);

        off = (type_sizes[type] - 1) << 3;
        for (i = 0; i < count / 3; i++) {
            uint32_t p = 0xFF000000;
            p |= (ff_tget(&pal_gb[0], type, s->le) >> off) << 16;
            p |= (ff_tget(&pal_gb[1], type, s->le) >> off) << 8;
            p |=  ff_tget(&pal_gb[2], type, s->le) >> off;
            s->palette[i] = p;
        }
        s->palette_is_set = 1;
        break;
    }
    case TIFF_PLANAR:
        s->planar = value == 2;
        break;
    case TIFF_YCBCR_SUBSAMPLING:
        if (count != 2) {
            av_log(s->avctx, AV_LOG_ERROR, "subsample count invalid\n");
            return AVERROR_INVALIDDATA;
        }
        for (i = 0; i < count; i++)
            s->subsampling[i] = ff_tget(&s->gb, type, s->le);
        break;
    case TIFF_T4OPTIONS:
        if (s->compr == TIFF_G3)
            s->fax_opts = value;
        break;
    case TIFF_T6OPTIONS:
        if (s->compr == TIFF_G4)
            s->fax_opts = value;
        break;
#define ADD_METADATA(count, name, sep)\
    if ((ret = add_metadata(count, type, name, sep, s, frame)) < 0) {\
        av_log(s->avctx, AV_LOG_ERROR, "Error allocating temporary buffer\n");\
        goto end;\
    }
    case TIFF_MODEL_PIXEL_SCALE:
        ADD_METADATA(count, "ModelPixelScaleTag", NULL);
        break;
    case TIFF_MODEL_TRANSFORMATION:
        ADD_METADATA(count, "ModelTransformationTag", NULL);
        break;
    case TIFF_MODEL_TIEPOINT:
        ADD_METADATA(count, "ModelTiepointTag", NULL);
        break;
    case TIFF_GEO_KEY_DIRECTORY:
        ADD_METADATA(1, "GeoTIFF_Version", NULL);
        ADD_METADATA(2, "GeoTIFF_Key_Revision", ".");
        s->geotag_count   = ff_tget_short(&s->gb, s->le);
        if (s->geotag_count > count / 4 - 1) {
            s->geotag_count = count / 4 - 1;
            av_log(s->avctx, AV_LOG_WARNING, "GeoTIFF key directory buffer shorter than specified\n");
        }
        if (bytestream2_get_bytes_left(&s->gb) < s->geotag_count * sizeof(int16_t) * 4) {
            s->geotag_count = 0;
            return -1;
        }
        s->geotags = av_mallocz_array(s->geotag_count, sizeof(TiffGeoTag));
        if (!s->geotags) {
            av_log(s->avctx, AV_LOG_ERROR, "Error allocating temporary buffer\n");
            s->geotag_count = 0;
            goto end;
        }
        for (i = 0; i < s->geotag_count; i++) {
            s->geotags[i].key    = ff_tget_short(&s->gb, s->le);
            s->geotags[i].type   = ff_tget_short(&s->gb, s->le);
            s->geotags[i].count  = ff_tget_short(&s->gb, s->le);

            if (!s->geotags[i].type)
                s->geotags[i].val  = get_geokey_val(s->geotags[i].key, ff_tget_short(&s->gb, s->le));
            else
                s->geotags[i].offset = ff_tget_short(&s->gb, s->le);
        }
        break;
    case TIFF_GEO_DOUBLE_PARAMS:
        if (count >= INT_MAX / sizeof(int64_t))
            return AVERROR_INVALIDDATA;
        if (bytestream2_get_bytes_left(&s->gb) < count * sizeof(int64_t))
            return AVERROR_INVALIDDATA;
        dp = av_malloc_array(count, sizeof(double));
        if (!dp) {
            av_log(s->avctx, AV_LOG_ERROR, "Error allocating temporary buffer\n");
            goto end;
        }
        for (i = 0; i < count; i++)
            dp[i] = ff_tget_double(&s->gb, s->le);
        for (i = 0; i < s->geotag_count; i++) {
            if (s->geotags[i].type == TIFF_GEO_DOUBLE_PARAMS) {
                if (s->geotags[i].count == 0
                    || s->geotags[i].offset + s->geotags[i].count > count) {
                    av_log(s->avctx, AV_LOG_WARNING, "Invalid GeoTIFF key %d\n", s->geotags[i].key);
                } else {
                    char *ap = doubles2str(&dp[s->geotags[i].offset], s->geotags[i].count, ", ");
                    if (!ap) {
                        av_log(s->avctx, AV_LOG_ERROR, "Error allocating temporary buffer\n");
                        av_freep(&dp);
                        return AVERROR(ENOMEM);
                    }
                    s->geotags[i].val = ap;
                }
            }
        }
        av_freep(&dp);
        break;
    case TIFF_GEO_ASCII_PARAMS:
        pos = bytestream2_tell(&s->gb);
        for (i = 0; i < s->geotag_count; i++) {
            if (s->geotags[i].type == TIFF_GEO_ASCII_PARAMS) {
                if (s->geotags[i].count == 0
                    || s->geotags[i].offset +  s->geotags[i].count > count) {
                    av_log(s->avctx, AV_LOG_WARNING, "Invalid GeoTIFF key %d\n", s->geotags[i].key);
                } else {
                    char *ap;

                    bytestream2_seek(&s->gb, pos + s->geotags[i].offset, SEEK_SET);
                    if (bytestream2_get_bytes_left(&s->gb) < s->geotags[i].count)
                        return AVERROR_INVALIDDATA;
                    ap = av_malloc(s->geotags[i].count);
                    if (!ap) {
                        av_log(s->avctx, AV_LOG_ERROR, "Error allocating temporary buffer\n");
                        return AVERROR(ENOMEM);
                    }
                    bytestream2_get_bufferu(&s->gb, ap, s->geotags[i].count);
                    ap[s->geotags[i].count - 1] = '\0'; //replace the "|" delimiter with a 0 byte
                    s->geotags[i].val = ap;
                }
            }
        }
        break;
    case TIFF_ARTIST:
        ADD_METADATA(count, "artist", NULL);
        break;
    case TIFF_COPYRIGHT:
        ADD_METADATA(count, "copyright", NULL);
        break;
    case TIFF_DATE:
        ADD_METADATA(count, "date", NULL);
        break;
    case TIFF_DOCUMENT_NAME:
        ADD_METADATA(count, "document_name", NULL);
        break;
    case TIFF_HOST_COMPUTER:
        ADD_METADATA(count, "computer", NULL);
        break;
    case TIFF_IMAGE_DESCRIPTION:
        ADD_METADATA(count, "description", NULL);
        break;
    case TIFF_MAKE:
        ADD_METADATA(count, "make", NULL);
        break;
    case TIFF_MODEL:
        ADD_METADATA(count, "model", NULL);
        break;
    case TIFF_PAGE_NAME:
        ADD_METADATA(count, "page_name", NULL);
        break;
    case TIFF_PAGE_NUMBER:
        ADD_METADATA(count, "page_number", " / ");
        break;
    case TIFF_SOFTWARE_NAME:
        ADD_METADATA(count, "software", NULL);
        break;
    default:
        if (s->avctx->err_recognition & AV_EF_EXPLODE) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "Unknown or unsupported tag %d/0X%0X\n",
                   tag, tag);
            return AVERROR_INVALIDDATA;
        }
    }
end:
    if (s->bpp > 64U) {
        av_log(s->avctx, AV_LOG_ERROR,
                "This format is not supported (bpp=%d, %d components)\n",
                s->bpp, count);
        s->bpp = 0;
        return AVERROR_INVALIDDATA;
    }
    bytestream2_seek(&s->gb, start, SEEK_SET);
    return 0;
}
