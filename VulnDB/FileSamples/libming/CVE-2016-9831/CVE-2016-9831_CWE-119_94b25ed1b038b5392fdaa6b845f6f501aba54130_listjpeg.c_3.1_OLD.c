
#include <stdlib.h>
#include <stdio.h>

/* JPEG stream markers: */
#define JPEG_MARKER 0xFF

/* Start of Image, End of Image */
#define JPEG_SOI  0xD8
#define JPEG_EOI  0xD9

#define JPEG_JFIF 0xE0

/* encoding markers, quantization tables and Huffman tables */
#define JPEG_QUANT 0xDB
#define JPEG_HUFF  0xC4

/* image markers, start of frame and start of scan */
#define JPEG_SOF0 0xC0
#define JPEG_SOF1 0xC1
#define JPEG_SOF2 0xC2
#define JPEG_SOS  0xDA

void printJpegStream(FILE *f)
{
  int c, l;

  while(!feof(f))
  {
    if(fgetc(f) != JPEG_MARKER)
    {
      printf("Jpeg marker not found!\n");
      break;
    }

    switch(c=fgetc(f))
    {
      case JPEG_SOI:   printf("SOI\n"); break;
      case JPEG_EOI:   printf("EOI\n"); break;
      case JPEG_JFIF:  printf("JFIF\n"); break;
      case JPEG_QUANT: printf("Quantization table\n"); break;
      case JPEG_HUFF:  printf("Huffman table\n"); break;
      case JPEG_SOF0:  printf("Start of frame 0\n"); break;
      case JPEG_SOF1:  printf("Start of frame 1\n"); break;
      case JPEG_SOF2:  printf("Start of frame 2\n"); break;
      case JPEG_SOS:   printf("Start of scan\n"); break;
      default:         printf("Unknown JPEG block: %02x\n", c);
    }

    if(c==JPEG_SOS)
      break;

    if(c != JPEG_SOI && c != JPEG_EOI)
    {
      l = (fgetc(f)<<8) + fgetc(f);
      printf("%i bytes\n", l);

      for(l-=2; l>0; --l)
	fgetc(f);
    }
  }
}

int main(int argc, char *argv[])
{
  FILE *f;

  f = fopen(argv[1], "rb");

  if(argc<1)
  {
    printf("Gimme file name\n");
    exit(1);
  }

  if(!f)
  {
    printf("Couldn't open file %s!\n", argv[1]);
    exit(1);
  }

  printJpegStream(f);
  exit(0);
}
