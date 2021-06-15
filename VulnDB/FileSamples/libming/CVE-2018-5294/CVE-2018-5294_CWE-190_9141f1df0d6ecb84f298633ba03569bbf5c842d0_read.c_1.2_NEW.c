/****************************************************************************
 *
 *  Copyright (C) 2011      Sandro Santilli <strk@kbt.io>
 *  Copyright (C) 2005-2006 Stuart R. Anderson <anderson@netsweng.com>
 *  Copyright (C) 2001      Raffaele Sena
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

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "parser.h"

int fileOffset = 0;

int buffer;
int bufbits = 0; /* # of bits in buffer */

void byteAlign()
{
  if(bufbits > 0)
  {
    bufbits = 0;
    buffer = 0;
  }
}

int readBits(FILE *f, int number)
{
  int ret = buffer;
  int tmp_char;

  if(number == bufbits)
  {
    bufbits = 0;
    buffer = 0;
    return ret;
  }

  if(number > bufbits)
  {
    number -= bufbits;

    while(number>8)
    {
      tmp_char = fgetc(f);
      if (tmp_char == EOF)
      {
        // exit here instead of crashing elswhere
        fprintf(stderr, "truncated file\n");
        exit(-1);
      }

      ret <<= 8;
      ret += tmp_char;
      ++fileOffset;
      number -= 8;
    }

    ++fileOffset;
    tmp_char = fgetc(f);
    if (tmp_char == EOF)
    {
      // exit here instead of crashing elswhere
      fprintf(stderr, "truncated file\n");
      exit(-1);
    }

    buffer = tmp_char;

    if(number>0)
    {
      ret <<= number;
      bufbits = 8-number;
      ret += buffer >> (8-number);
      buffer &= (1<<bufbits)-1;
    }

    return ret;
  }

  ret = buffer >> (bufbits-number);
  bufbits -= number;
  buffer &= (1<<bufbits)-1;

  return ret;
}

int readSBits(FILE *f, int number)
{
  int num = readBits(f, number);

  if(number && num & (1<<(number-1)))
    return num - (1<<number);
  else
    return num;
}

void readRect(FILE *f, struct Rect *s)
{
  int nBits;
  byteAlign();

  nBits = readBits(f, 5);
  s->xMin = readSBits(f, nBits);
  s->xMax = readSBits(f, nBits);
  s->yMin = readSBits(f, nBits);
  s->yMax = readSBits(f, nBits);
}

int readUInt8(FILE *f)
{
  int tmp_char = fgetc(f);
  // the rest of the code does not handle errors and use EOF as a valid unsigned char value
  if (tmp_char == EOF)
  {
    // exit here instead of crashing elswhere
    fprintf(stderr, "truncated file\n");
    exit(-1);
  }

  bufbits = 0;
  ++fileOffset;
  return tmp_char;
}

int readSInt8(FILE *f)
{
  return (signed char)readUInt8(f);
}

int readSInt16(FILE *f)
{
  int result = 0;
  result |= readUInt8(f);
  result |= readSInt8(f) << 8;
  return result;
}

unsigned int readUInt16(FILE *f)
{
  unsigned int result = 0u;
  result |= readUInt8(f);
  result |= readUInt8(f) << 8;
  return result;
}

long readSInt32(FILE *f)
{
  long result = 0;
  result |= readUInt8(f);
  result |= readUInt8(f) << 8;
  result |= readUInt8(f) << 16;
  result |= (long) readUInt8(f) << 24;
  return result;
}

unsigned long readUInt32(FILE *f)
{
  unsigned long result = 0u;
  result |= readUInt8(f);
  result |= readUInt8(f) << 8;
  result |= readUInt8(f) << 16;
  result |= (unsigned long) readUInt8(f) << 24;
  return result;
}

double readDouble(FILE *f)
{
  union {
    char c[8];
    double d;
  } data;

#ifdef SWF_LITTLE_ENDIAN
  data.c[4] = readUInt8(f);
  data.c[5] = readUInt8(f);
  data.c[6] = readUInt8(f);
  data.c[7] = readUInt8(f);
  data.c[0] = readUInt8(f);
  data.c[1] = readUInt8(f);
  data.c[2] = readUInt8(f);
  data.c[3] = readUInt8(f);
#else
  data.c[3] = readUInt8(f);
  data.c[2] = readUInt8(f);
  data.c[1] = readUInt8(f);
  data.c[0] = readUInt8(f);
  data.c[7] = readUInt8(f);
  data.c[6] = readUInt8(f);
  data.c[5] = readUInt8(f);
  data.c[4] = readUInt8(f);
#endif


  return data.d;
}

float readFloat(FILE *f)
{
  union {
    char c[4];
    float f;
  } data;

#ifdef SWF_LITTLE_ENDIAN
  data.c[0] = readUInt8(f);
  data.c[1] = readUInt8(f);
  data.c[2] = readUInt8(f);
  data.c[3] = readUInt8(f);
#else
  data.c[3] = readUInt8(f);
  data.c[2] = readUInt8(f);
  data.c[1] = readUInt8(f);
  data.c[0] = readUInt8(f);
#endif

  return data.f;
}


char *readBytes(FILE *f, unsigned long size)
{

  if (size < 1) {
#if DEBUG
    SWF_warn("readBytes: want to read %lu < 1 bytes: Handling a 0\n", size);
#endif
    size = 0;
  }

  unsigned long i;
  char *buf;

  buf = (char *)malloc(sizeof(char)*size);

  if (buf == NULL) {
    fprintf(stderr, "readBytes: Failed to allocate %lu bytes", sizeof(char) * size);
    exit(-1);
  }

  for(i=0;i<size;i++)
  {
    buf[i]=(char)readUInt8(f);
  }

  return buf;
}

char *readString(FILE *f)
{
  unsigned int len = 0, buflen = 256;
  char c, *buf, *p;

  buf = (char *)malloc(sizeof(char)*buflen);
  if ( ! buf )
  {
    fprintf(stderr, "failed allocating %d bytes\n", buflen);
    exit(-1);
  }
  p = buf;

  while((c=(char)readUInt8(f)) != '\0')
  {
    if(len >= buflen-2)
    {
      if ( buflen >= UINT_MAX - 256 )
      {
        fprintf(stderr, "string null-termination missing after reading %d bytes, giving up\n", buflen);
        exit(-1);
      }
      buflen += 256;
      buf = (char *)realloc(buf, sizeof(char)*(buflen));
      if ( ! buf )
      {
        fprintf(stderr, "failed allocating %d bytes\n", buflen);
        exit(-1);
      }
      p = buf+len;
    }

    switch(c)
    {
      case '\n':
	*(p++) = '\\';	*(p++) = 'n';	++len;	break;
      case '\t':
	*(p++) = '\\';	*(p++) = 't';	++len;	break;
      case '\r':
	*(p++) = '\\';	*(p++) = 'r';	++len;	break;
      default:
	*(p++) = c;
    }

    ++len;
  }

  *p = 0;

  return buf;
}

#define ENC_BITSPERBYTE 	7
#define ENC_BYTEMASK 		0x7f
#define ENC_U30_VERIFY		0xfc
#define ENC_HIGHBIT		0x80

static inline int hasNextByte(unsigned int b)
{
	if(!(b & ENC_HIGHBIT))
		return 0;
	return 1;
}

signed long readEncSInt32(FILE *f)
{
	signed long result = 0, temp;
	int shift = 0;
	do
	{
		if(shift > 4 * ENC_BITSPERBYTE)
			break;

		temp = readUInt8(f);	
		result |= (ENC_BYTEMASK & temp) << shift;
		shift += ENC_BITSPERBYTE;
	} while (hasNextByte(temp));
	return result;
}

unsigned long readEncUInt30(FILE *f)
{
	unsigned long result = 0, temp;
	int shift = 0;
	do
	{
		if(shift > 4 * ENC_BITSPERBYTE)
			break;
		
		temp = readUInt8(f);
		result |= (ENC_BYTEMASK & temp) << shift;
		shift += ENC_BITSPERBYTE;
	} while (hasNextByte(temp));
	
	//if((temp & ENC_U30_VERIFY) && shift > 4 * ENC_BITSPERBYTE)
	//	printf("readEncUInt30: verification error\n"); 

	return result;
}

unsigned long readEncUInt32(FILE *f)
{
	unsigned long result = 0, temp;
	int shift = 0;
	do
	{
		if(shift > 4 * ENC_BITSPERBYTE)
			break;
		
		temp = readUInt8(f);
		result |= (ENC_BYTEMASK & temp) << shift;
		shift += ENC_BITSPERBYTE;
	} while (hasNextByte(temp));
	
	return result;
}

char *readSizedString(FILE *f,int size)
{
  int len = 0, buflen = 256, i;
  char c, *buf, *p;

  buf = (char *)malloc(sizeof(char)*buflen);
  p = buf;

  for(i=0;i<size;i++)
  {
    c=(char)readUInt8(f);
    if(len >= buflen-2)
    {
      buf = (char *)realloc(buf, sizeof(char)*(buflen+256));
      if ( ! buf )
      {
        fprintf(stderr, "failed reallocating %d bytes\n", buflen+256);
        exit(-1);
      }
      buflen += 256;
      p = buf+len;
    }

    switch(c)
    {
      case '\n':
	*(p++) = '\\';	*(p++) = 'n';	++len;	break;
      case '\t':
	*(p++) = '\\';	*(p++) = 't';	++len;	break;
      case '\r':
	*(p++) = '\\';	*(p++) = 'r';	++len;	break;
      default:
	*(p++) = c;
    }

    ++len;
  }

  *p = 0;

  return buf;
}

void _dumpBytes(FILE *f, int length, int restore)
{
  int j=0, i, k, l=0, offset=0;
  unsigned char buf[16];

  if(length<=0)
    return;

  if(restore) 
	  offset = ftell(f);

  putchar('\n');

  for(;; ++l)
  {
    printf("%03x0: ", l);
    for(i=0; i<16; ++i)
    {
      if(i==8) putchar(' ');

      printf("%02x ", buf[i] = readUInt8(f));
      ++j;

      if(j==length)
		break;
    }

    if(j==length)
    {
      for(k=i+1; k<16; ++k)
	printf("   ");

      if(k==8) putchar(' ');

      ++i;
    }

    printf("   ");

    for(k=0; k<i; ++k)
    {
      if(k==8) putchar(' ');

      if((buf[k] > 31) && (buf[k] < 128))
	putchar(buf[k]);
      else
	putchar('.');
    }

    putchar('\n');

    if(j==length)
      break;
  }
  putchar('\n');
  putchar('\n');

  if(restore) {
	fseek(f,offset, SEEK_SET);
  	fileOffset = offset;
  }
}

void dumpBytes(FILE *f, int length)
{
	_dumpBytes(f, length, 0 );
}

void peekBytes(FILE *f, int length)
{
	_dumpBytes(f, length, 1 );
}

void dumpBuffer(unsigned char *buf, int length)
{
  int j=0, i, k, l=0;

  if(length<=0)
    return;

  putchar('\n');

  for(;; ++l)
  {
    printf("%03x0: ", l);

    for(i=0; i<16; ++i)
    {
      if(i==8) putchar(' ');

      printf("%02x ", buf[16*l+i]);
      ++j;

      if(j==length)
		break;
    }

    if(j==length)
    {
      for(k=i+1; k<16; ++k)
	printf("   ");

      if(k==8) putchar(' ');

      ++i;
    }

    printf("   ");

    for(k=0; k<i; ++k)
    {
      if(k==8) putchar(' ');

      if((buf[16*l+k] > 31) && (buf[16*l+k] < 128))
	putchar(buf[16*l+k]);
      else
	putchar('.');
    }

    putchar('\n');

    if(j==length)
      break;
  }

  putchar('\n');
  putchar('\n');
}

void silentSkipBytes(FILE *f, int length)
{
  for(; length>0; --length)
    readUInt8(f);
}


