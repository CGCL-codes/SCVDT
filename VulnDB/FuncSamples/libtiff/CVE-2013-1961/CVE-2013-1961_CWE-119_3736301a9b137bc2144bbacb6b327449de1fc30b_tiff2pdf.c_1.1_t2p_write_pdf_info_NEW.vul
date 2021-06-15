tsize_t t2p_write_pdf_info(T2P* t2p, TIFF* input, TIFF* output)
{
	tsize_t written = 0;
	char* info;
	char buffer[512];

	if(t2p->pdf_datetime[0] == '\0')
		t2p_pdf_tifftime(t2p, input);
	if (strlen(t2p->pdf_datetime) > 0) {
		written += t2pWriteFile(output, (tdata_t) "<< \n/CreationDate ", 18);
		written += t2p_write_pdf_string(t2p->pdf_datetime, output);
		written += t2pWriteFile(output, (tdata_t) "\n/ModDate ", 10);
		written += t2p_write_pdf_string(t2p->pdf_datetime, output);
	}
	written += t2pWriteFile(output, (tdata_t) "\n/Producer ", 11);
	snprintf(buffer, sizeof(buffer), "libtiff / tiff2pdf - %d", TIFFLIB_VERSION);
	written += t2p_write_pdf_string(buffer, output);
	written += t2pWriteFile(output, (tdata_t) "\n", 1);
	if (t2p->pdf_creator[0] != '\0') {
		written += t2pWriteFile(output, (tdata_t) "/Creator ", 9);
		written += t2p_write_pdf_string(t2p->pdf_creator, output);
		written += t2pWriteFile(output, (tdata_t) "\n", 1);
	} else {
		if (TIFFGetField(input, TIFFTAG_SOFTWARE, &info) != 0 && info) {
			if(strlen(info) >= sizeof(t2p->pdf_creator))
				info[sizeof(t2p->pdf_creator) - 1] = '\0';
			written += t2pWriteFile(output, (tdata_t) "/Creator ", 9);
			written += t2p_write_pdf_string(info, output);
			written += t2pWriteFile(output, (tdata_t) "\n", 1);
		}
	}
	if (t2p->pdf_author[0] != '\0') {
		written += t2pWriteFile(output, (tdata_t) "/Author ", 8);
		written += t2p_write_pdf_string(t2p->pdf_author, output);
		written += t2pWriteFile(output, (tdata_t) "\n", 1);
	} else {
		if ((TIFFGetField(input, TIFFTAG_ARTIST, &info) != 0
		     || TIFFGetField(input, TIFFTAG_COPYRIGHT, &info) != 0)
		    && info) {
			if (strlen(info) >= sizeof(t2p->pdf_author))
				info[sizeof(t2p->pdf_author) - 1] = '\0';
			written += t2pWriteFile(output, (tdata_t) "/Author ", 8);
			written += t2p_write_pdf_string(info, output);
			written += t2pWriteFile(output, (tdata_t) "\n", 1);
		}
	}
	if (t2p->pdf_title[0] != '\0') {
		written += t2pWriteFile(output, (tdata_t) "/Title ", 7);
		written += t2p_write_pdf_string(t2p->pdf_title, output);
		written += t2pWriteFile(output, (tdata_t) "\n", 1);
	} else {
		if (TIFFGetField(input, TIFFTAG_DOCUMENTNAME, &info) != 0){
			if(strlen(info) > 511) {
				info[512] = '\0';
			}
			written += t2pWriteFile(output, (tdata_t) "/Title ", 7);
			written += t2p_write_pdf_string(info, output);
			written += t2pWriteFile(output, (tdata_t) "\n", 1);
		}
	}
	if (t2p->pdf_subject[0] != '\0') {
		written += t2pWriteFile(output, (tdata_t) "/Subject ", 9);
		written += t2p_write_pdf_string(t2p->pdf_subject, output);
		written += t2pWriteFile(output, (tdata_t) "\n", 1);
	} else {
		if (TIFFGetField(input, TIFFTAG_IMAGEDESCRIPTION, &info) != 0 && info) {
			if (strlen(info) >= sizeof(t2p->pdf_subject))
				info[sizeof(t2p->pdf_subject) - 1] = '\0';
			written += t2pWriteFile(output, (tdata_t) "/Subject ", 9);
			written += t2p_write_pdf_string(info, output);
			written += t2pWriteFile(output, (tdata_t) "\n", 1);
		}
	}
	if (t2p->pdf_keywords[0] != '\0') {
		written += t2pWriteFile(output, (tdata_t) "/Keywords ", 10);
		written += t2p_write_pdf_string(t2p->pdf_keywords, output);
		written += t2pWriteFile(output, (tdata_t) "\n", 1);
	}
	written += t2pWriteFile(output, (tdata_t) ">> \n", 4);

	return(written);
}
