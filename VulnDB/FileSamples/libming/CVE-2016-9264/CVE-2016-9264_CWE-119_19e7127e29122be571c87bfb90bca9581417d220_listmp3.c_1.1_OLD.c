#include <stdlib.h>
#include <stdio.h>

#define error(x)	{puts(x); exit(1);}

#define MP3_FRAME_SYNC       0xFFE00000

#define MP3_VERSION          0x00180000
#define MP3_VERSION_25       0x00000000
#define MP3_VERSION_RESERVED 0x00080000
#define MP3_VERSION_2        0x00100000
#define MP3_VERSION_1        0x00180000

#define MP3_LAYER            0x00060000
#define MP3_LAYER_RESERVED   0x00000000
#define MP3_LAYER_3          0x00020000
#define MP3_LAYER_2          0x00040000
#define MP3_LAYER_1          0x00060000

#define MP3_PROTECT          0x00010000 /* 16-bit CRC after header */

#define MP3_BITRATE          0x0000F000
#define MP3_BITRATE_SHIFT    12

int mp1l1_bitrate_table[] = { 0,   32,   64,  96, 128, 160, 192, 224,
			      256, 288, 320, 352, 382, 416, 448 };

int mp1l2_bitrate_table[] = { 0,   32,   48,  56,  64,  80,  96, 112,
			      128, 160, 192, 224, 256, 320, 384 };

int mp1l3_bitrate_table[] = { 0,    32,  40,  48,  56,  64,  80,  96,
			      112, 128, 160, 192, 224, 256, 320 };

int mp2l1_bitrate_table[] = { 0,    32,  48,  56,  64,  80,  96, 112,
			      128, 144, 160, 176, 192, 224, 256 };

int mp2l23_bitrate_table[] = { 0,    8,  16,  24,  32,  40,  48,  56,
			       64,  80,  96, 112, 128, 144, 160 };

#define MP3_SAMPLERATE       0x00000C00
#define MP3_SAMPLERATE_SHIFT 10

int mp1_samplerate_table[] = { 44100, 48000, 32000 };
int mp2_samplerate_table[] = { 22050, 24000, 16000 }; /* is this right?? */
int mp25_samplerate_table[] = { 11025, 12000, 8000 }; /* fewer samples?? */

#define MP3_PADDING          0x00000200 /* if set, add an extra slot - 4 bytes
					   for layer 1, 1 byte for 2+3 */

#define MP3_CHANNEL          0x000000C0
#define MP3_CHANNEL_STEREO   0x00000000
#define MP3_CHANNEL_JOINT    0x00000040
#define MP3_CHANNEL_DUAL     0x00000080
#define MP3_CHANNEL_MONO     0x000000C0

/* rest of the header info doesn't affect frame size.. */

void skipBytes(FILE *f, int length)
{
  for(; length>0; --length)
    if(fgetc(f) == EOF)
      return;
}

void printMP3Headers(FILE *f)
{
  unsigned long flags;
  int frameLen, numFrames = 0;
  int bitrate=0, bitrate_idx, samplerate=0, samplerate_idx;
  int version, layer, channels, padding;
  int bitrateSum = 0;
  int length;

  for(;;)
  {
    /* get 4-byte header, bigendian */
    if((flags = fgetc(f)) == EOF)
      break;

    /* XXX - fix this mad hackery */
    if(flags == 'I' && fgetc(f) == 'D' && fgetc(f) == '3')
    {
      do
      {
	flags = fgetc(f);
      }
      while(flags != 0xFF && flags != EOF);
    }

    if(flags == EOF)
      break;

    flags <<= 24;
    flags += fgetc(f) << 16;
    flags += fgetc(f) << 8;
    flags += fgetc(f);

    if((flags & MP3_FRAME_SYNC) != MP3_FRAME_SYNC)
      break;
    /*      error("bad sync on MP3 block!"); */

    ++numFrames;

    bitrate_idx = (flags & MP3_BITRATE) >> MP3_BITRATE_SHIFT;
    samplerate_idx = (flags & MP3_SAMPLERATE) >> MP3_SAMPLERATE_SHIFT;

    channels = ((flags & MP3_CHANNEL) == MP3_CHANNEL_MONO) ? 1 : 2;

    switch(flags & MP3_VERSION)
    {
      case MP3_VERSION_1:  version = 1; break;
      case MP3_VERSION_2:  version = 2; break;
      case MP3_VERSION_25: version = 25; break;
      default: error("unknown MP3 version!");
    }
    switch(flags & MP3_LAYER)
    {
      case MP3_LAYER_1: layer = 1; break;
      case MP3_LAYER_2: layer = 2; break;
      case MP3_LAYER_3: layer = 3; break;
      default: error("unknown MP3 layer!");
    }

    bitrateSum += bitrate;

    if(version == 1)
    {
      samplerate = mp1_samplerate_table[samplerate_idx];

      if(layer == 1)
	bitrate = mp1l1_bitrate_table[bitrate_idx];

      else if(layer == 2)
	bitrate = mp1l2_bitrate_table[bitrate_idx];

      else if(layer == 3)
	bitrate = mp1l3_bitrate_table[bitrate_idx];
    }
    else
    {
      if(version == 2)
	samplerate = mp2_samplerate_table[samplerate_idx];
      else
	samplerate = mp25_samplerate_table[samplerate_idx];

      if(layer == 1)
	bitrate = mp2l1_bitrate_table[bitrate_idx];
      else
	bitrate = mp2l23_bitrate_table[bitrate_idx];
    }

    padding = (flags & MP3_PADDING) ? 1 : 0;

    if(layer == 1)
      padding <<= 2;

    if(version == 1)
      frameLen = 144 * bitrate * 1000 / samplerate + padding;
    else
      frameLen = 72 * bitrate * 1000 / samplerate + padding;

    printf("frame %i: MP%i layer %i, %i Hz, %ikbps, %s, length=%i, protect %s\n",
	   numFrames, version, layer, samplerate, bitrate,
	   (channels==2) ? "stereo" : "mono", frameLen,
	   (flags&MP3_PROTECT) ? "on" : "off");

    skipBytes(f, frameLen-4);
  }

  putchar('\n');

  length = numFrames*(samplerate > 3200 ? 1152 : 576)/samplerate;

  printf("Number of frames: %i\n", numFrames);
  printf("Average bitrate: %i\n", bitrateSum/numFrames);
  printf("Length: %i:%02i\n", length/60, length%60);
}

int main(int argc, char *argv[])
{
  FILE *f;

  if(argc<1)
    error("gimme file name");

  f = fopen(argv[1],"rb");

  if(!f)
    error("couldn't open file");

  printMP3Headers(f);

  exit(0);
}
