PHP_FUNCTION(imagegammacorrect)
{
	zval *IM;
	gdImagePtr im;
	int i;
	double input, output;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rdd", &IM, &input, &output) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(im, gdImagePtr, &IM, -1, "Image", le_gd);

	if (gdImageTrueColor(im))	{
		int x, y, c;

		for (y = 0; y < gdImageSY(im); y++)	{
			for (x = 0; x < gdImageSX(im); x++)	{
				c = gdImageGetPixel(im, x, y);
				gdImageSetPixel(im, x, y,
					gdTrueColorAlpha(
						(int) ((pow((pow((gdTrueColorGetRed(c)   / 255.0), input)), 1.0 / output) * 255) + .5),
						(int) ((pow((pow((gdTrueColorGetGreen(c) / 255.0), input)), 1.0 / output) * 255) + .5),
						(int) ((pow((pow((gdTrueColorGetBlue(c)  / 255.0), input)), 1.0 / output) * 255) + .5),
						gdTrueColorGetAlpha(c)
					)
				);
			}
		}
		RETURN_TRUE;
	}

	for (i = 0; i < gdImageColorsTotal(im); i++) {
		im->red[i]   = (int)((pow((pow((im->red[i]   / 255.0), input)), 1.0 / output) * 255) + .5);
		im->green[i] = (int)((pow((pow((im->green[i] / 255.0), input)), 1.0 / output) * 255) + .5);
		im->blue[i]  = (int)((pow((pow((im->blue[i]  / 255.0), input)), 1.0 / output) * 255) + .5);
	}

	RETURN_TRUE;
}
