void jas_matrix_clip(jas_matrix_t *matrix, jas_seqent_t minval, jas_seqent_t maxval)
{
	int i;
	int j;
	jas_seqent_t v;
	jas_seqent_t *rowstart;
	jas_seqent_t *data;
	int rowstep;

	rowstep = jas_matrix_rowstep(matrix);
	for (i = matrix->numrows_, rowstart = matrix->rows_[0]; i > 0; --i,
	  rowstart += rowstep) {
		data = rowstart;
		for (j = matrix->numcols_, data = rowstart; j > 0; --j,
		  ++data) {
			v = *data;
			if (v < minval) {
				*data = minval;
			} else if (v > maxval) {
				*data = maxval;
			}
		}
	}
}
