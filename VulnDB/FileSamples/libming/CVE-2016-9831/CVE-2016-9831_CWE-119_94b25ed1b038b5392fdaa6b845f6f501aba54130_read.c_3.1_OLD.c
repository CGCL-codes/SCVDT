
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int fileOffset = 0;

int gIndent = 0;
char indentBuf[256];
int lastIndent = 0;

void error(char *s, ...)
{
  va_list ap;
  va_start(ap, s);
  vprintf(s, ap);
  va_end(ap);
  putchar('\n');
  exit(-1);
}

void warning(char *s, ...)
{
  va_list ap;
  va_start(ap, s);
  vprintf(s, ap);
  va_end(ap);
  putchar('\n');
}

char *indent()
{
  int i;

  if(gIndent>63)
    error("indent level > 63!");

  if(lastIndent != gIndent)
  {
    for(i=0; i<3*gIndent; ++i)
      indentBuf[i] = ' ';

    indentBuf[i] = '\0';

    lastIndent = gIndent;
  }

  return indentBuf;
}

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
      ret <<= 8;
      ret += fgetc(f);
      ++fileOffset;
      number -= 8;
    }

    ++fileOffset;
    buffer = fgetc(f);

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

  if(num & (1<<(number-1)))
    return num - (1<<number);
  else
    return num;
}

int readUInt8(FILE *f)
{
  bufbits = 0;
  ++fileOffset;
  return fgetc(f);
}

int readSInt8(FILE *f)
{
  return (signed char)readUInt8(f);
}

int readSInt16(FILE *f)
{
  return readUInt8(f) + readSInt8(f)*256;
}

int readUInt16(FILE *f)
{
  return readUInt8(f) + (readUInt8(f)<<8);
}

long readSInt32(FILE *f)
{
  return (long)readUInt8(f) + (readUInt8(f)<<8) + (readUInt8(f)<<16) + (readUInt8(f)<<24);
}

unsigned long readUInt32(FILE *f)
{
  return (unsigned long)(readUInt8(f) + (readUInt8(f)<<8) + (readUInt8(f)<<16) + (readUInt8(f)<<24));
}

double readDouble(FILE *f)
{
  char data[8];

  data[4] = readUInt8(f);
  data[5] = readUInt8(f);
  data[6] = readUInt8(f);
  data[7] = readUInt8(f);
  data[0] = readUInt8(f);
  data[1] = readUInt8(f);
  data[2] = readUInt8(f);
  data[3] = readUInt8(f);

  return *((double *)data);
}

char *readString(FILE *f)
{
  int len = 0, buflen = 256;
  char c, *buf, *p;

  buf = (char *)malloc(sizeof(char)*256);
  p = buf;

  while((c=(char)readUInt8(f)) != '\0')
  {
    if(len >= buflen-2)
    {
      buf = (char *)realloc(buf, sizeof(char)*(buflen+256));
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

void dumpBytes(FILE *f, int length)
{
  int j=0, i, k, l=0;
  unsigned char buf[16];

  if(length<=0)
    return;

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
