tsize_t t2p_write_pdf_name(unsigned char* name, TIFF* output){

	tsize_t written=0;
	uint32 i=0;
	char buffer[64];
	uint16 nextchar=0;
	size_t namelen=0;
	
	namelen = strlen((char *)name);
	if (namelen>126) {
		namelen=126;
	}
	written += t2pWriteFile(output, (tdata_t) "/", 1);
	for (i=0;i<namelen;i++){
		if ( ((unsigned char)name[i]) < 0x21){
			snprintf(buffer, sizeof(buffer), "#%.2X", name[i]);
			buffer[sizeof(buffer) - 1] = '\0';
			written += t2pWriteFile(output, (tdata_t) buffer, 3);
			nextchar=1;
		}
		if ( ((unsigned char)name[i]) > 0x7E){
			snprintf(buffer, sizeof(buffer), "#%.2X", name[i]);
			buffer[sizeof(buffer) - 1] = '\0';
			written += t2pWriteFile(output, (tdata_t) buffer, 3);
			nextchar=1;
		}
		if (nextchar==0){
			switch (name[i]){
				case 0x23:
					snprintf(buffer, sizeof(buffer), "#%.2X", name[i]);
					buffer[sizeof(buffer) - 1] = '\0';
					written += t2pWriteFile(output, (tdata_t) buffer, 3);
					break;
				case 0x25:
					snprintf(buffer, sizeof(buffer), "#%.2X", name[i]);
					buffer[sizeof(buffer) - 1] = '\0';
					written += t2pWriteFile(output, (tdata_t) buffer, 3);
					break;
				case 0x28:
					snprintf(buffer, sizeof(buffer), "#%.2X", name[i]);
					buffer[sizeof(buffer) - 1] = '\0';
					written += t2pWriteFile(output, (tdata_t) buffer, 3);
					break;
				case 0x29:
					snprintf(buffer, sizeof(buffer), "#%.2X", name[i]); 
					buffer[sizeof(buffer) - 1] = '\0';
					written += t2pWriteFile(output, (tdata_t) buffer, 3);
					break;
				case 0x2F:
					snprintf(buffer, sizeof(buffer), "#%.2X", name[i]); 
					buffer[sizeof(buffer) - 1] = '\0';
					written += t2pWriteFile(output, (tdata_t) buffer, 3);
					break;
				case 0x3C:
					snprintf(buffer, sizeof(buffer), "#%.2X", name[i]); 
					buffer[sizeof(buffer) - 1] = '\0';
					written += t2pWriteFile(output, (tdata_t) buffer, 3);
					break;
				case 0x3E:
					snprintf(buffer, sizeof(buffer), "#%.2X", name[i]);
					buffer[sizeof(buffer) - 1] = '\0';
					written += t2pWriteFile(output, (tdata_t) buffer, 3);
					break;
				case 0x5B:
					snprintf(buffer, sizeof(buffer), "#%.2X", name[i]); 
					buffer[sizeof(buffer) - 1] = '\0';
					written += t2pWriteFile(output, (tdata_t) buffer, 3);
					break;
				case 0x5D:
					snprintf(buffer, sizeof(buffer), "#%.2X", name[i]);
					buffer[sizeof(buffer) - 1] = '\0';
					written += t2pWriteFile(output, (tdata_t) buffer, 3);
					break;
				case 0x7B:
					snprintf(buffer, sizeof(buffer), "#%.2X", name[i]); 
					buffer[sizeof(buffer) - 1] = '\0';
					written += t2pWriteFile(output, (tdata_t) buffer, 3);
					break;
				case 0x7D:
					snprintf(buffer, sizeof(buffer), "#%.2X", name[i]); 
					buffer[sizeof(buffer) - 1] = '\0';
					written += t2pWriteFile(output, (tdata_t) buffer, 3);
					break;
				default:
					written += t2pWriteFile(output, (tdata_t) &name[i], 1);
			}
		}
		nextchar=0;
	}
	written += t2pWriteFile(output, (tdata_t) " ", 1);

	return(written);
}
