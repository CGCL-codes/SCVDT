/*
    Ming, an SWF output library
    Copyright (C) 2002  Opaque Industries - http://www.opaque.net/

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* $Id$ */

#ifndef __C2MAN__
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#endif

#ifndef WIN32
#include <unistd.h>
#endif

#include "libming.h"
#include "input.h"
#include "method.h"
#include "error.h"


struct SWFInput_s
{
	void (*destroy)(SWFInput This);
	int (*getChar)(SWFInput This);
	int (*read)(SWFInput This, unsigned char* buffer, int count);
	void (*seek)(SWFInput This, long offset, int whence);
	int (*eof)(SWFInput This);

	int offset;
	int length;
	void *data;
#if TRACK_ALLOCS
	/* memory node for garbage collection */
	mem_node *gcnode;
#endif
	int buffer;
	int bufbits;
};

void
SWFInput_byteAlign(SWFInput input)
{
	if(input->bufbits > 0)
	{
		input->bufbits = 0;
		input->buffer = 0;
	}
}

int
SWFInput_readBits(SWFInput input, int number)
{
	int ret = input->buffer;
	if ( number == input->bufbits )
	{
		input->bufbits = 0;
		input->buffer = 0;
		return ret;
	}

	if ( number > input->bufbits )
	{
		number -= input->bufbits;

		while( number > 8 )
		{
			ret <<= 8;
			ret += SWFInput_getChar(input);
			number -= 8;
		}
		
		input->buffer = SWFInput_getChar(input);
		
		if ( number > 0 )
		{
			ret <<= number;
			input->bufbits = 8-number;
			ret += input->buffer >> (8-number);
			input->buffer &= (1<<input->bufbits)-1;
		}

		return ret;
	}

	ret = input->buffer >> (input->bufbits-number);
	input->bufbits -= number;
	input->buffer &= (1<<input->bufbits)-1;
//	printf("done: readBits(%i) numer < bufbits %i\n", number, ret);
	return ret;
}

int 
SWFInput_readSBits(SWFInput input, int number)
{
	int num = SWFInput_readBits(input, number);

	if ( num & (1<<(number-1)) )
		return num - (1<<number);
	else
		return num;
}

int
SWFInput_getChar(SWFInput input)
{
	return input->getChar(input);
}


int
SWFInput_getUInt16(SWFInput input)
{
	int num = SWFInput_getChar(input);
	num += SWFInput_getChar(input) << 8;
	return num;
}


int
SWFInput_getUInt16_BE(SWFInput input)
{
	int num = SWFInput_getChar(input) << 8;
	num += SWFInput_getChar(input);
	return num;
}


int
SWFInput_getSInt16(SWFInput input)
{
	int num = SWFInput_getChar(input);
	num += SWFInput_getChar(input) * 256;
	return num;
}


unsigned long 
SWFInput_getUInt24_BE(SWFInput input)
{
	unsigned long num = SWFInput_getChar(input) << 16;
	num += SWFInput_getChar(input) << 8;
	num += SWFInput_getChar(input);
	return num;
}

unsigned long
SWFInput_getUInt32(SWFInput input)
{
	unsigned long num = SWFInput_getChar(input);
	num += SWFInput_getChar(input) << 8;
	num += SWFInput_getChar(input) << 16;
	num += SWFInput_getChar(input) << 24;
	return num;
}


unsigned long
SWFInput_getUInt32_BE(SWFInput input)
{
	unsigned long num = SWFInput_getChar(input) << 24;
	num += SWFInput_getChar(input) << 16;
	num += SWFInput_getChar(input) << 8;
	num += SWFInput_getChar(input);
	return num;
}


int
SWFInput_read(SWFInput input, unsigned char* buffer, int count)
{
	return input->read(input, buffer, count);
}


void
SWFInput_seek(SWFInput input, long offset, int whence)
{
	input->seek(input, offset, whence);
}


int
SWFInput_length(SWFInput input)
{
	int pos = SWFInput_tell(input);

	SWFInput_seek(input, 0, SEEK_END);
	SWFInput_seek(input, pos, SEEK_SET);

	return input->length;
}


int
SWFInput_eof(SWFInput input)
{
	return input->eof(input);
}


int
SWFInput_tell(SWFInput input)
{
	return input->offset;
}


void
SWFInput_rewind(SWFInput input)
{
	SWFInput_seek(input, 0, SEEK_SET);
}


void
destroySWFInput(SWFInput input)
{
	input->destroy(input);
}


static void
SWFInput_dtor(SWFInput input)
{
#if TRACK_ALLOCS
	ming_gc_remove_node(input->gcnode);
#endif
	free(input);
}


/* SWFInput_file */

static void
SWFInput_file_seek(SWFInput input, long offset, int whence)
{
	if ( fseek((FILE *)input->data, offset, whence) == -1 )
	{
		if ( errno == EBADF )
			SWF_error("This is not a seekable stream- use newSWFInput_stream instead");
		else if ( errno == EINVAL )
			SWF_error("Invalid whence argument");
		else
			SWF_error("Unknown error");
	}

	if ( whence == SEEK_SET )
		input->offset = offset;

	else if ( whence == SEEK_END )
		input->offset = input->length - offset;

	else if ( whence == SEEK_CUR )
		input->offset += offset;
}


static int
SWFInput_file_eof(SWFInput input)
{
	return feof((FILE *)input->data);
}


static int
SWFInput_file_getChar(SWFInput input)
{
	int c = fgetc((FILE *)input->data);

	if ( c == EOF )
		input->length = input->offset;
	else
		++input->offset;

	return c;
}

static int SWFInput_file_read(SWFInput input, unsigned char *buffer, int count)
{	int len = fread(buffer, 1, count, (FILE *)input->data);
	input->offset += len;
	return len;
}

SWFInput
newSWFInput_file(FILE *f)
{
	SWFInput input;
	struct stat buf;

	/* XXX - doesn't check for validity of f.. */

	if ( fseek(f, 0, SEEK_CUR) == -1 )
		return newSWFInput_stream(f);

	if ( fstat(fileno(f), &buf) == -1 )
		SWF_error("Couldn't fstat filehandle in newSWFInput_file");;

	input = (SWFInput) malloc(sizeof(struct SWFInput_s));

	/* If malloc failed, return NULL to signify this */
	if (NULL == input)
		return NULL;

	input->getChar = SWFInput_file_getChar;
	input->destroy = SWFInput_dtor;
	input->eof = SWFInput_file_eof;
	input->seek = SWFInput_file_seek;
	input->read = SWFInput_file_read;
	input->data = f;
	input->bufbits = 0;
	input->buffer = 0;
	input->offset = 0;
	input->length = buf.st_size;

#if TRACK_ALLOCS
	input->gcnode = ming_gc_add_node(input, (dtorfunctype) destroySWFInput);
#endif

	return input;
}

static void SWFInput_dtor_close(SWFInput input)
{
	fclose((FILE *)input->data);
	SWFInput_dtor(input);
}


SWFInput
newSWFInput_filename(const char *filename)
{
	FILE *file;
	SWFInput input;
	
	file = fopen(filename, "rb");
	if(file == NULL)
	{
		SWF_warn("newSWFInput_filename: %s: %s\n",
			filename, strerror(errno));
		return NULL;
	}

	input = newSWFInput_file(file);
	if(input == NULL)
		return NULL;

	input->destroy = SWFInput_dtor_close;
	return input;
}


/* SWFInput_buffer */

static int
SWFInput_buffer_getChar(SWFInput input)
{
	if ( input->offset >= input->length )
		return EOF;
	else
		return ((unsigned char *)input->data)[input->offset++];
}


static int
SWFInput_buffer_eof(SWFInput input)
{
	return input->offset >= input->length;
}


static int
SWFInput_buffer_read(SWFInput input, unsigned char* buffer, int count)
{
	if ( count > input->length - input->offset )
		count = input->length - input->offset;

	memcpy(buffer, (unsigned char*)input->data + input->offset, count);
	input->offset += count;

	return count;
}


static void
SWFInput_buffer_seek(SWFInput input, long offset, int whence)
{
	if ( whence == SEEK_CUR )
	{
		if ( offset >= 0 )
			input->offset = min(input->length, input->offset + offset);
		else
			input->offset = max(0, input->offset + offset);
	}

	else if ( whence == SEEK_END )
		input->offset = max(0, input->length - offset);

	else if ( whence == SEEK_SET )
		input->offset = min(input->length, offset);
}


SWFInput
newSWFInput_buffer(unsigned char* buffer, int length)
{
	SWFInput input = (SWFInput) malloc(sizeof(struct SWFInput_s));

	/* If malloc failed, return NULL to signify this */
	if (NULL == input)
		return NULL;

	input->getChar = SWFInput_buffer_getChar;
	input->destroy = SWFInput_dtor;
	input->eof = SWFInput_buffer_eof;
	input->read = SWFInput_buffer_read;
	input->seek = SWFInput_buffer_seek;
	input->data = buffer;
	input->buffer = 0;
	input->bufbits = 0;
	input->offset = 0;
	input->length = length;

#if TRACK_ALLOCS
	input->gcnode = ming_gc_add_node(input, (dtorfunctype) destroySWFInput);
#endif

	return input;
}


static void
SWFInput_buffer_dtor(SWFInput input)
{
	free(input->data);
#if TRACK_ALLOCS
	ming_gc_remove_node(input->gcnode);
#endif
	free(input);
}


/* same as above but needs to be freed */
SWFInput
newSWFInput_allocedBuffer(unsigned char *buffer, int length)
{
	SWFInput input = newSWFInput_buffer(buffer, length);
	input->destroy = SWFInput_buffer_dtor;
#if TRACK_ALLOCS
	input->gcnode = ming_gc_add_node(input, (dtorfunctype) destroySWFInput);
#endif
	return input;
}

/* same as above but copy buffer and  needs to be freed */
SWFInput
newSWFInput_bufferCopy(unsigned char *buffer, int length)
{
	SWFInput input;
	unsigned char *data = (unsigned char *)malloc(length);
	if(data == NULL)
		return NULL;

	memcpy(data, buffer, length);
	input = newSWFInput_buffer(data, length);
	input->destroy = SWFInput_buffer_dtor;
#if TRACK_ALLOCS
	input->gcnode = ming_gc_add_node(input, (dtorfunctype) destroySWFInput);
#endif
	return input;
}




/* SWFInput_stream */

#define INPUTSTREAM_INCREMENT 32768
#define MAX_INPUTSTREAM (32*1024*1024) // 32 mb

struct SWFInputStreamData
{
	FILE *file;
	unsigned char *buffer;
};


static void
SWFInput_stream_seek(SWFInput input, long offset, int whence)
{
	int len, l, readOffset;
	struct SWFInputStreamData *data;

	if ( whence == SEEK_CUR )
		input->offset = input->offset + offset;

	else if ( whence == SEEK_SET )
		input->offset = offset;

	else if ( whence == SEEK_END )
	{
		/* suck data until EOF */
		/* XXX - might want to put a limit on how much we suck (ha) */

		while ( SWFInput_getChar(input) != EOF )
			if (input->length > MAX_INPUTSTREAM)
				break;

		input->offset = input->length - offset;
	}

	if (input->offset < 0)
		input->offset = 0;

	if ( input->offset < input->length )
		return;

	/* now slurp up as much data as we need to get here */

	len = (((input->offset - input->length)/INPUTSTREAM_INCREMENT)+1) * INPUTSTREAM_INCREMENT;

	readOffset = input->length;
	input->length += len;
	data = (struct SWFInputStreamData*) input->data;

	data->buffer = (unsigned char*)realloc(data->buffer, sizeof(unsigned char) * (input->length + len));

	l=1; /* just to initialize to something */
	while((len > 0) && (l > 0))
	{
		l = fread(data->buffer, sizeof(unsigned char), len, data->file);
		len -= l;
		readOffset += l;
	}
}


static int
SWFInput_stream_getChar(SWFInput input)
{
	struct SWFInputStreamData *data = (struct SWFInputStreamData *) input->data;

	if (input->offset >= MAX_INPUTSTREAM)
		return EOF;

	if ( input->offset == input->length )
	{
		/* fetch from stream, save in buffer */

		FILE *f = data->file;
		int c = fgetc(f);

		++input->offset;

		if ( c != EOF )
		{
			if ( input->length % INPUTSTREAM_INCREMENT == 0 )
			{
				data->buffer = (unsigned char*) realloc(data->buffer,
															 sizeof(unsigned char) *
															 (input->length + INPUTSTREAM_INCREMENT));
			}

			data->buffer[input->length] = c;
			++input->length;
		}

		return c;
	}
	else if ( input->offset < input->length )
	{
		/* fetch from buffer */
		return data->buffer[input->offset++];
	}
	else
		return EOF;
}


static int
SWFInput_stream_read(SWFInput input, unsigned char* buffer, int count)
{
	struct SWFInputStreamData *data = (struct SWFInputStreamData *) input->data;
	int need = input->offset + count - input->length;

	if ( need > 0 )
	{
		int num;

		data->buffer =
			(unsigned char*) realloc(data->buffer,
							sizeof(unsigned char) * INPUTSTREAM_INCREMENT *
							(((input->offset + count) / INPUTSTREAM_INCREMENT) + 1));
		
		num = fread(data->buffer + input->length,
								sizeof(unsigned char), need, data->file);

		input->length += num;
	}

	if ( count > input->length - input->offset )
		count = input->length - input->offset;

	memcpy(buffer, data->buffer + input->offset, count);

	return count;
}




static void
SWFInput_stream_dtor(SWFInput input)
{
	free(input->data);
#if TRACK_ALLOCS
	ming_gc_remove_node(input->gcnode);
#endif
	free(input);
}

static int SWFInput_stream_eof(SWFInput input)
{
	return ((input->offset >= input->length) ? feof((FILE *)input->data) : 0);
}

SWFInput
newSWFInput_stream(FILE* f)
{
	SWFInput input = (SWFInput)malloc(sizeof(struct SWFInput_s));
	struct SWFInputStreamData *data;

	/* If malloc failed, return NULL to signify this */
	if (NULL == input)
		return NULL;

	data = (struct SWFInputStreamData *)malloc(sizeof(struct SWFInputStreamData));

	/* If malloc failed, free memory allocated for input and return NULL to signify the failure */
	if (NULL == data)
	{
		free(input);
		return NULL;
	}

	input->getChar = SWFInput_stream_getChar;
	input->destroy = SWFInput_stream_dtor;
	input->eof = SWFInput_stream_eof;
	input->read = SWFInput_stream_read;
	input->seek = SWFInput_stream_seek;

	input->offset = 0;
	input->length = 0;
	input->buffer = 0;
	input->bufbits = 0;

	data->file = f;
	data->buffer = NULL;

	input->data = (void *)data;

#if TRACK_ALLOCS
	input->gcnode = ming_gc_add_node(input, (dtorfunctype) destroySWFInput);
#endif

	return input;
}


struct SWFInputPtr
{
	SWFInput input;
	unsigned int offset;
};

static int
SWFInput_input_getChar(SWFInput input)
{
	struct SWFInputPtr *ptr;
 	int old_offset, result;

	if ( input->offset >= input->length )
		return EOF;
		
	ptr = (struct SWFInputPtr *)input->data;
	old_offset = SWFInput_tell(ptr->input);
 
	SWFInput_seek(ptr->input, ptr->offset + input->offset, SEEK_SET);
	result = SWFInput_getChar(ptr->input);
	input->offset++;
	SWFInput_seek(ptr->input, old_offset, SEEK_SET);

	return result;
}


static void
SWFInput_input_seek(SWFInput input, long offset, int whence)
{
	if ( whence == SEEK_CUR )
	{
		if ( offset >= 0 )
			input->offset = min(input->length, input->offset + offset);
		else
			input->offset = max(0, input->offset + offset);
	}

	else if ( whence == SEEK_END )
		input->offset = max(0, input->length - offset);

	else if ( whence == SEEK_SET )
		input->offset = min(input->length, offset);
}


static int
SWFInput_input_eof(SWFInput input)
{
	return input->offset >= input->length;
}

static void
SWFInput_input_dtor(SWFInput input)
{
	free(input->data);
#if TRACK_ALLOCS
	ming_gc_remove_node(input->gcnode);
#endif
	free(input);
}


static int
SWFInput_input_read(SWFInput input, unsigned char* buffer, int count)
{
	int ret;
	struct SWFInputPtr *ptr;
	int old_offset;

	if ( count > input->length - input->offset )
		count = input->length - input->offset;

	ptr = (struct SWFInputPtr *)input->data;
        old_offset = SWFInput_tell(ptr->input);
	SWFInput_seek(ptr->input, ptr->offset + input->offset, SEEK_SET);

	ret = SWFInput_read((SWFInput)ptr->input, buffer, count);
	if(ret != count)
		SWF_warn("SWFInput_input_read: ret %i, count %i\n", ret, count);
	input->offset += count;

	SWFInput_seek(ptr->input, old_offset, SEEK_SET);

	return count;
}

SWFInput
newSWFInput_input(SWFInput in, unsigned int length)
{
	SWFInput input;
	struct SWFInputPtr *data;

	if (in == NULL)
		return NULL;

	input = (SWFInput)malloc(sizeof(struct SWFInput_s));

	/* If malloc failed, return NULL to signify this */
	if (NULL == input)
		return NULL;

	input->getChar = SWFInput_input_getChar;
	input->destroy = SWFInput_input_dtor;
	input->eof = SWFInput_input_eof;
	input->read = SWFInput_input_read;
	input->seek = SWFInput_input_seek;

	data = (struct SWFInputPtr *)malloc(sizeof(struct SWFInputPtr));

	/* If malloc failed, free memory allocated for input and return NULL to signify the failure */
	if (NULL == data)
	{
		free(input);
		return NULL;
	}

	data->offset = SWFInput_tell(in);
	data->input = in;

	input->offset = 0;
	input->length = length;

	input->data = (void *)data;
	input->buffer = 0;
	input->bufbits = 0;
#if TRACK_ALLOCS
	input->gcnode = ming_gc_add_node(input, (dtorfunctype) destroySWFInput);
#endif

	return input;
}
/*
 * Local variables:
 * tab-width: 2
 * c-basic-offset: 2
 * End:
 */
