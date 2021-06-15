static void php_imagepolygon(INTERNAL_FUNCTION_PARAMETERS, int filled)
{
	zval *IM, *POINTS;
	long NPOINTS, COL;
	zval **var = NULL;
	gdImagePtr im;
	gdPointPtr points;
	int npoints, col, nelem, i;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rall", &IM, &POINTS, &NPOINTS, &COL) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(im, gdImagePtr, &IM, -1, "Image", le_gd);

	npoints = NPOINTS;
	col = COL;

	nelem = zend_hash_num_elements(Z_ARRVAL_P(POINTS));
	if (nelem < 6) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "You must have at least 3 points in your array");
		RETURN_FALSE;
	}
	if (npoints <= 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "You must give a positive number of points");
		RETURN_FALSE;
	}
	if (nelem < npoints * 2) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Trying to use %d points in array with only %d points", npoints, nelem/2);
		RETURN_FALSE;
	}

	points = (gdPointPtr) safe_emalloc(npoints, sizeof(gdPoint), 0);

	for (i = 0; i < npoints; i++) {
		if (zend_hash_index_find(Z_ARRVAL_P(POINTS), (i * 2), (void **) &var) == SUCCESS) {
			SEPARATE_ZVAL((var));
			convert_to_long(*var);
			points[i].x = Z_LVAL_PP(var);
		}
		if (zend_hash_index_find(Z_ARRVAL_P(POINTS), (i * 2) + 1, (void **) &var) == SUCCESS) {
			SEPARATE_ZVAL(var);
			convert_to_long(*var);
			points[i].y = Z_LVAL_PP(var);
		}
	}

	if (filled) {
		gdImageFilledPolygon(im, points, npoints, col);
	} else {
		gdImagePolygon(im, points, npoints, col);
	}

	efree(points);
	RETURN_TRUE;
}
