/****************************************************************************
 *
 *  Copyright (C) 2005-2006 "Stuart R. Anderson" <anderson@netsweng.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 ****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

//open()
#include <fcntl.h>

//fstat()
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ming_config.h"

//decompression
#ifdef USE_ZLIB
#include <zlib.h>
#endif

#include "blocks/blocktypes.h"
#include "action.h"
#include "parser.h"
#include "read.h"
#include "swfoutput.h"

SWF_Parserstruct *blockParse (FILE *f, int length, SWFBlocktype header);
const char *blockName (SWFBlocktype header);

char *filename;
char tmp_name[PATH_MAX];
FILE *tempfile;
char *swftargetfile=NULL;
struct Movie m;
int verbose = 0;

#if USE_ZLIB
/*
 * Compressed swf-files have a 8 Byte uncompressed header and a
 * zlib-compressed body. 
 */
int
cws2fws(FILE *f, uLong outsize)
{

	struct stat statbuffer;
	int insize, ret;
	int err,tmp_fd;
	Byte *inbuffer,*outbuffer;

	sprintf(tmp_name, "/tmp/swftoscriptXXXXXX");

#ifdef HAVE_MKSTEMP
	tmp_fd = mkstemp(tmp_name);
#endif
#ifndef HAVE_MKSTEMP
	tmp_fd = open(tmp_name, O_RDWR | O_CREAT | O_TRUNC , 0600);
#endif

	if ( tmp_fd == -1 )
	{
		SWF_error("Couldn't create tempfile.\n");
	}

	tempfile = fdopen(tmp_fd, "w+");
	if ( ! tempfile )
	{
		SWF_error("fdopen: %s", strerror(errno));
	}


	if( stat(filename, &statbuffer) == -1 )
	{
		SWF_error("stat() failed on input file");
	}
	
	insize = statbuffer.st_size-8;
	inbuffer = malloc(insize);
	if(!inbuffer){ SWF_error("malloc() failed"); }
	if ( ! fread(inbuffer, insize, 1, f) )
	{
		SWF_error("Error reading input file");
	}
	
	/* We don't trust the value in the swfheader. */
	outbuffer=NULL;
	do{
		outbuffer = realloc(outbuffer, outsize);	
		if (!outbuffer) { SWF_error("malloc(%lu) failed",outsize); }

		/* uncompress the data */
		err=uncompress(outbuffer,&outsize,inbuffer,insize);
		switch(err){
			case Z_MEM_ERROR:
				SWF_error("Not enough memory.\n");
				break;
			case Z_BUF_ERROR:
				SWF_warn("resizing outbuffer..\n");
				outsize*=2;
				continue;
			case Z_DATA_ERROR:
				SWF_error("Data corrupted. Couldn't uncompress.\n");
				break;
			case Z_OK:
				break;
			default:
				SWF_error("Unknown returnvalue of uncompress:%i\n",
					err);
				break;
		}
	} while(err == Z_BUF_ERROR);
 
	/* Rebuild the header so the file offsets will be right */
	fputc('F',tempfile);
	fputc('W',tempfile);
	fputc('S',tempfile);
	fputc(m.version,tempfile);
	ret = fwrite(&m.size,sizeof(int),1,tempfile);
	if(ret != 1)
		SWF_error("cws2fws: failed writing file size\n");

	if ( outsize != fwrite(outbuffer, 1, outsize, tempfile) )
	{
		SWF_error("Error writing uncompressed");
	}

	rewind(tempfile);
	return (int)outsize;
}
#endif

static void usage(char *prog)
{
#ifdef MAKE_FDB
	fprintf(stderr,"%s: [-v] inputfile\n", prog);
	fprintf(stderr,"<inputfile> should be a swf files containing font blocks (DEFINEFONT2).\n");
	fprintf(stderr,"For every fontblock found a .fdb file is wirtten with the associated font name.\n\n");
#else
	fprintf(stderr,"%s: [-v] inputfile [swftargetfile]\n", prog);
#endif
}

static int filelen_check_fails(int minLength)
{
	if(m.size - fileOffset < minLength)
	{
		SWF_warn("sudden file end: read failed @%i fileSize %i, request %i\n", 
				fileOffset, m.size, minLength);
		return -1;
	}
	return 0;
}

static int readMovieHeader(FILE *f, int *compressed)
{
	char first;
	struct stat stat_buf;
	
	first = readUInt8 (f);
	*compressed = (first == ('C')) ? 1 : 0;
	if (!((first == 'C' || first == 'F') && readUInt8 (f) == 'W'
		&& readUInt8 (f) == 'S'))
	{
		SWF_error ("Doesn't look like a swf file to me..\n");
	}

	m.version = readUInt8 (f);
	m.size = readUInt32 (f);
	m.soundStreamFmt = -1;
	m.fonts = NULL;
	m.numFonts = 0;
	if (*compressed)
	{
#if USE_ZLIB
		int unzipped = cws2fws (f, m.size);
		if (m.size != (unzipped + 8))
		{
			SWF_warn ("m.size: %i != %i+8  Maybe wrong value in swfheader.\n", m.size, unzipped + 8);
			m.size = unzipped +8;
		}
		fclose (f);
		f = tempfile;
		fseek(f,8,SEEK_SET);
#else

		/* No zlib, so we can't uncompress the data */
		SWF_error("No zlib support compiled in, "
			"cannot read compressed SWF");
#endif
	}
	else 
	{
		if(fstat(fileno(f), &stat_buf) < 0) // verify file size!
		{
			perror("stat failed: ");
			return -1;
		}	
		if(m.size != stat_buf.st_size)
		{
			SWF_warn("header indicates a filesize of %lu but filesize is %lu\n", m.size, stat_buf.st_size);
			m.size = stat_buf.st_size; 
		}
	}
	readRect (f, &(m.frame));

	m.rate = readUInt8 (f) / 256.0 + readUInt8 (f);
	m.nFrames = readUInt16 (f);
	outputHeader(&m);
	return 0;
}

static void readMovie(FILE *f)
{
	int block, type, blockstart, blockoffset, length, nextFrame=0;
	SWF_Parserstruct *blockp;
	for (;;)
	{
		blockoffset = fileOffset;

		// printf ("Block offset: %d %d\n", fileOffset, m.size);

		if(filelen_check_fails(2))
			break;
		block = readUInt16 (f);
		type = block >> 6;

		length = block & ((1 << 6) - 1);

		if (length == 63)		/* it's a long block. */ 
		{
			if(filelen_check_fails(4))
				break;
			length = readUInt32 (f);
		}
		
		//      printf ("Found Block: %s (%i), %i bytes\n", blockName (type), type, length);
		blockstart = fileOffset;
		nextFrame = fileOffset+length;
		
		if(filelen_check_fails(length))
			break;
		blockp= blockParse(f, length, type);

		if( ftell(f) != nextFrame ) 
		{
			// will SEEK_SET later, so this is not a critical error
		        SWF_warn(" Stream out of sync after parse of blocktype %d (%s)."
				" %ld but expecting %d.\n", type, blockName(type),
				ftell(f),nextFrame);
		}

		if( blockp ) 
		{
			outputBlock( type, blockp, f);
			free(blockp);	
		} else {
			SWF_warn("Error parsing block (unknown block type: %d, length %d)\n", 
				type, length);
		}

		if (type == 0 || fileOffset >= m.size)
			break;
	
		fseek(f, nextFrame, SEEK_SET);
		fileOffset = ftell(f);
	}
	putchar ('\n');

	if (fileOffset < m.size)
	{
		SWF_warn("extra garbage (i.e., we messed up in main): \n");
		dumpBytes (f, m.size - fileOffset);
		printf ("\n\n");
	}
	outputTrailer(&m);
}


int
main (int argc, char *argv[])
{
	FILE *f;
	int compressed = 0;

	setbuf(stdout, NULL);
	switch( argc ) 
	{
	case 2:
		filename = argv[1];
		break;
	case 3:
		if (strcmp (argv[1], "-v") == 0) {
			verbose = 1;
			filename = argv[2];
		} else {
			filename = argv[1];
			swftargetfile = argv[2];
		}
		break;
	case 4:
		if (strcmp (argv[1], "-v") != 0) {
			usage(argv[0]);
			exit(1);
		}
		verbose = 1;
		filename = argv[2];
		swftargetfile = argv[3];
		break;
	case 0:
	case 1:
	default:
		usage(argv[0]);
		exit(1);
	}
	
	if (!(f = fopen (filename, "rb")))
	{
		fprintf(stderr,"Sorry, can't seem to read the file '%s'\n",filename);
		usage(argv[0]);
		exit(1);
	}

	if(readMovieHeader(f, &compressed))
		SWF_error("reading movie header failed\n");
	if(compressed)	
		f = tempfile;
	readMovie(f);
	fclose (f);
	if (compressed)
	{
		unlink (tmp_name);
	}
	exit (0);
}
