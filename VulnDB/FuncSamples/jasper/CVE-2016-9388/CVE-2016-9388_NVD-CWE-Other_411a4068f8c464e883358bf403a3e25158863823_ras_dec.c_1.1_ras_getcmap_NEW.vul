static int ras_getcmap(jas_stream_t *in, ras_hdr_t *hdr, ras_cmap_t *cmap)
{
	int i;
	int j;
	int x;
	int c;
	int numcolors;
	int actualnumcolors;

	switch (hdr->maptype) {
	case RAS_MT_NONE:
		break;
	case RAS_MT_EQUALRGB:
		{
		jas_eprintf("warning: palettized images not fully supported\n");
		numcolors = 1 << hdr->depth;
		if (numcolors > RAS_CMAP_MAXSIZ) {
			return -1;
		}
		actualnumcolors = hdr->maplength / 3;
		for (i = 0; i < numcolors; i++) {
			cmap->data[i] = 0;
		}
		if ((hdr->maplength % 3) || hdr->maplength < 0 ||
		  hdr->maplength > 3 * numcolors) {
			return -1;
		}
		for (i = 0; i < 3; i++) {
			for (j = 0; j < actualnumcolors; j++) {
				if ((c = jas_stream_getc(in)) == EOF) {
					return -1;
				}
				x = 0;
				switch (i) {
				case 0:
					x = RAS_RED(c);
					break;
				case 1:
					x = RAS_GREEN(c);
					break;
				case 2:
					x = RAS_BLUE(c);
					break;
				}
				cmap->data[j] |= x;
			}
		}
		}
		break;
	default:
		return -1;
		break;
	}

	return 0;
}
