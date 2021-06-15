
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

#include "blocks/blocktypes.h"
#include "action.h"
#include "read.h"
#include "decompile.h"


#ifdef NODECOMPILE
#define decompileAction(f,l,n) printDoAction((f),(l))
#else
#define decompileAction(f,l,n) printDecompiledAction((f),(l),(n))
#endif

/*#define decompileAction(f,l) dumpBytes((f),(l))*/

#define puts(s) fputs((s),stdout)

/* char *blockName(SWFBlocktype type); */
void skipBytes(FILE *f, int length);
extern const char *blockName(int header);

#define INDENT_LEVEL 3

void print(const char *s, ...)
{
  va_list ap;
  int n = gIndent*INDENT_LEVEL;

  while(n-- > 0)
    putchar(' ');

  va_start(ap, s);
  vprintf(s, ap);
  va_end(ap);
}
void println(const char *s, ...)
{
  va_list ap;
  int n = gIndent*INDENT_LEVEL;

  while(n-- > 0)
    putchar(' ');

  va_start(ap, s);
  vprintf(s, ap);
  va_end(ap);

  putchar('\n');
}

void printMatrix(FILE *f)
{
  int nBits;
  float num;

  byteAlign();

  if(readBits(f, 1)) /* has scale */
  {
    nBits = readBits(f, 5);
    num = (float)readSBits(f, nBits)/0x10000;
    println("xScale: %f", num);
    num = (float)readSBits(f, nBits)/0x10000;
    println("yScale: %f", num);
  }
  if(readBits(f, 1)) /* has rotate */
  {
    nBits = readBits(f, 5);
    num = (float)readSBits(f, nBits)/0x10000;
    println("rotate0: %f", num);
    num = (float)readSBits(f, nBits)/0x10000;
    println("rotate1: %f", num);
  }

  nBits = readBits(f, 5);
  println("x: %i", readSBits(f, nBits));
  println("y: %i", readSBits(f, nBits));
}

void printCXForm(FILE *f, boolean hasAlpha)
{
  int hasAdd, hasMult, nBits;

  byteAlign();

  hasAdd = readBits(f, 1);
  hasMult = readBits(f, 1);
  nBits = readBits(f, 4);

  if(hasMult)
  {
    puts("x(");
    printf("%i,", readSBits(f, nBits));
    printf("%i,", readSBits(f, nBits));
    printf("%i)", readSBits(f, nBits));
    if(hasAlpha)
      printf("%i,", readSBits(f, nBits));
  }
  else puts("x()");

  if(hasAdd)
  {
    puts("+(");
    printf("%i,", readSBits(f, nBits));
    printf("%i,", readSBits(f, nBits));
    printf("%i)", readSBits(f, nBits));
    if(hasAlpha)
      printf("%i,", readSBits(f, nBits));
  }
  else puts("+()");

  putchar('\n');
}


void printRect(FILE *f)
{
  int nBits, xMin, xMax, yMin, yMax;

  byteAlign();

  nBits = readBits(f, 5);
  xMin = readSBits(f, nBits);
  xMax = readSBits(f, nBits);
  yMin = readSBits(f, nBits);
  yMax = readSBits(f, nBits);

  printf("(%i,%i)x(%i,%i)", xMin, xMax, yMin, yMax);
}

void printRGB(FILE *f)
{
  int r = readUInt8(f);
  int g = readUInt8(f);
  int b = readUInt8(f);

  printf("(%02x,%02x,%02x)", r, g, b);
}

void printRGBA(FILE *f)
{
  int r = readUInt8(f);
  int g = readUInt8(f);
  int b = readUInt8(f);
  int a = readUInt8(f);

  printf("(%02x,%02x,%02x,%02x)", r, g, b, a);
}

void printGradient(FILE *f, int shapeType)
{
  int i;
  int numGrads = readUInt8(f);

  for(i=0; i<numGrads; ++i)
  {
    print("Grad[%i]: ratio=%i, ", i, readUInt8(f));
    puts("color=");

    if(shapeType==SWF_DEFINESHAPE3)
      printRGBA(f);
    else
      printRGB(f);

    putchar('\n');
  }
}

void printMorphGradient(FILE *f)
{
  int i;
  int numGrads = readUInt8(f);

  for(i=0; i<numGrads; ++i)
  {
    print("Shape 1, Grad[%i]: ratio=%i, ", i, readUInt8(f));
    puts("color=");
    printRGBA(f);
    putchar('\n');

    print("Shape 2, Grad[%i]: ratio=%i, ", i, readUInt8(f));
    puts("color=");
    printRGBA(f);
    putchar('\n');
  }
}

void printLineStyleArray(FILE *f, int shapeType)
{
  int count, i;

  count = readUInt8(f);

  if(count==255)
    count = readUInt16(f);

  for(i=0; i<count; ++i)
  {
    print("LineStyle %i: ", i+1);
    printf("width=%i ", readUInt16(f));

    if(shapeType==SWF_DEFINEMORPHSHAPE)
      printf("width2=%i ", readUInt16(f));

    puts("color=");

    if(shapeType==SWF_DEFINESHAPE3 || shapeType==SWF_DEFINEMORPHSHAPE)
      printRGBA(f);
    else
      printRGB(f);

    if(shapeType==SWF_DEFINEMORPHSHAPE)
    {
      puts("color2=");
      printRGBA(f);
    }

    putchar('\n');
  }
}

void printFillStyle(FILE *f, int shapeType)
{
  int type;
	
  type = readUInt8(f);

  if(type==0) /* solid fill */
  {
    print("color=");

    if(shapeType==SWF_DEFINESHAPE3 || shapeType==SWF_DEFINEMORPHSHAPE)
      printRGBA(f);
    else
      printRGB(f);

    if(shapeType==SWF_DEFINEMORPHSHAPE)
    {
      print("color2=");
      printRGBA(f);
    }

    putchar('\n');
  }
  else if(type==0x10) /* linear */
  {
    println("Matrix:");
    ++gIndent;
    printMatrix(f);
    --gIndent;

    if(shapeType==SWF_DEFINEMORPHSHAPE)
    {
      println("Matrix2:");
      ++gIndent;
      printMatrix(f);
      --gIndent;
    }

    println("Gradient (linear):");
    ++gIndent;
    if(shapeType==SWF_DEFINEMORPHSHAPE)
      printMorphGradient(f);
    else
      printGradient(f, shapeType);
    --gIndent;
  }
  else if(type==0x12) /* radial gradient */
  {
    println("Matrix:");
    ++gIndent;
    printMatrix(f);
    --gIndent;

    if(shapeType==SWF_DEFINEMORPHSHAPE)
    {
      println("Matrix2:");
      ++gIndent;
      printMatrix(f);
      --gIndent;
    }

    println("Gradient (radial):");
    ++gIndent;
    if(shapeType==SWF_DEFINEMORPHSHAPE)
      printMorphGradient(f);
    else
      printGradient(f, shapeType);
    --gIndent;
  }
  else if(type==0x40) /* tiled bitmap */
  {
    println("Bitmap id: %i (tiled)", readUInt16(f));
    println("Bitmap matrix:");
    ++gIndent;
    printMatrix(f);
    --gIndent;

    if(shapeType==SWF_DEFINEMORPHSHAPE)
    {
      println("Bitmap matrix:");
      ++gIndent;
      printMatrix(f);
      --gIndent;
    }
  }
  else if(type==0x41) /* clipped bitmap */
  {
    println("Bitmap id: %i (clipped)", readUInt16(f));
    println("Bitmap matrix:");
    ++gIndent;
    printMatrix(f);
    --gIndent;

    if(shapeType==SWF_DEFINEMORPHSHAPE)
    {
      println("Bitmap matrix:");
      ++gIndent;
      printMatrix(f);
      --gIndent;
    }
  }
  else
    println("Unknown fill type: %i", type);
}

void printFillStyleArray(FILE *f, int shapeType)
{
  int count, i;

  count = readUInt8(f);

  if(count==255)
    count = readUInt16(f);

  for(i=0; i<count; ++i)
  {
    println("FillStyle %i:", i+1);
    ++gIndent;
    printFillStyle(f, shapeType);
    --gIndent;
    putchar('\n');
  }
}

int printShapeRec(FILE *f, int *lineBits, int *fillBits, int shapeType)
{
  int type;

  //  printf("(%i:%i)",fileOffset,bufbits);

  type = readBits(f, 1);

  if(type==0) /* state change */
  {
    int newStyles = readBits(f, 1);
    int lineStyle = readBits(f, 1);
    int fillStyle1 = readBits(f, 1);
    int fillStyle0 = readBits(f, 1);
    int moveTo = readBits(f, 1);

    if(newStyles==0 && lineStyle==0 && fillStyle1==0 && fillStyle0==0 && moveTo==0)
    {
      println("EndShape");
      return 0;
    }

    if(moveTo==1)
    {
      int moveBits = readBits(f, 5);
      int x = readSBits(f, moveBits);
      int y = readSBits(f, moveBits);

      println("MoveTo (%i) - (%i,%i)", moveBits, x, y);
    }

    if(fillStyle0==1)
      println("FillStyle0: %i", readBits(f, *fillBits));

    if(fillStyle1==1)
      println("FillStyle1: %i", readBits(f, *fillBits));

    if(lineStyle==1)
      println("LineStyle1: %i", readBits(f, *lineBits));

    if(newStyles==1)
    {
      println("NewStyles:");
      printFillStyleArray(f, shapeType);
      printLineStyleArray(f, shapeType);
      *fillBits = readBits(f, 4);
      *lineBits = readBits(f, 4);
    }
  }
  else /* it's an edge record */
  {
    int straight = readBits(f, 1);
    int numBits = readBits(f, 4)+2;

    if(straight==1)
    {
      if(readBits(f, 1)) /* general line */
      {
	int x = readSBits(f, numBits);
	int y = readSBits(f, numBits);

	println("StraightEdge: (%i) - (%i,%i)", numBits, x, y);
      }
      else
	if(readBits(f, 1)) /* vert = 1 */
	  println("StraightEdge: (%i) - (0,%i)", numBits, readSBits(f, numBits));
	else
	  println("StraightEdge: (%i) - (%i,0)", numBits, readSBits(f, numBits));
    }
    else
    {
      int controlX = readSBits(f, numBits);
      int controlY = readSBits(f, numBits);
      int anchorX = readSBits(f, numBits);
      int anchorY = readSBits(f, numBits);
      println("CurvedEdge: (%i) - (%i,%i)->(%i,%i)", numBits, controlX, controlY, anchorX, anchorY);
    }
  }

  return 1;
}

void printShape(FILE *f, int length, SWFBlocktype type)
{
  int start = fileOffset;
  int fillBits, lineBits;

  println("ShapeID: %i", readUInt16(f));

  print("Bounds: ");
  printRect(f);

  putchar('\n');
  putchar('\n');

  printFillStyleArray(f, type);
  printLineStyleArray(f, type);

  putchar('\n');

  byteAlign();

  fillBits = readBits(f,4);
  lineBits = readBits(f,4);

  while(fileOffset < length+start &&
	printShapeRec(f, &lineBits, &fillBits, type)) ;

  /* go for end tag..
  if(fileOffset == length+start && bufbits > 5)
    printShapeRec(f, &lineBits, &fillBits, type);
  */

  putchar('\n');
}

void printMorphShape(FILE *f, int length)
{
  int offset, start = fileOffset;
  int fillBits, lineBits, here;

  println("ShapeID: %i", readUInt16(f));

  print("Bounds1: ");
  printRect(f);
  putchar('\n');
  print("Bounds2: ");
  printRect(f);
  putchar('\n');

  offset = readUInt32(f);
  println("(%i)\toffset = %i", fileOffset, offset);

  here = fileOffset;

  printFillStyleArray(f, SWF_DEFINEMORPHSHAPE);
  printLineStyleArray(f, SWF_DEFINEMORPHSHAPE);

  fillBits = readBits(f, 4);
  lineBits = readBits(f, 4);

  putchar('\n');
  println("Shape1:");
  while(fileOffset < here+offset)
    printShapeRec(f, &lineBits, &fillBits, SWF_DEFINESHAPE3);

  byteAlign();

  /* ??? */
  fillBits = readBits(f, 4);
  lineBits = readBits(f, 4);

  putchar('\n');
  println("Shape2:");
  while(fileOffset < start+length)
    printShapeRec(f, &lineBits, &fillBits, SWF_DEFINESHAPE3);
}

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

void printJpegStream(FILE *f, int length)
{
  int end = fileOffset+length;
  int c, l;

  while(fileOffset < end)
  {
    if(readUInt8(f) != JPEG_MARKER)
    {
      println("Jpeg marker not found!");
      break;
    }

    switch(c=readUInt8(f))
    {
      case JPEG_SOI:   println("SOI"); break;
      case JPEG_EOI:   println("EOI"); break;
      case JPEG_JFIF:  println("JFIF"); break;
      case JPEG_QUANT: println("Quantization table"); break;
      case JPEG_HUFF:  println("Huffman table"); break;
      case JPEG_SOF0:  println("Start of frame 0"); break;
      case JPEG_SOF1:  println("Start of frame 1"); break;
      case JPEG_SOF2:  println("Start of frame 2"); break;
      case JPEG_SOS:   println("Start of scan"); break;
      default:         println("Unknown JPEG block: %02x", c);
    }

    if(c==JPEG_SOS)
      break;

    if(c != JPEG_SOI && c != JPEG_EOI)
    {
      l = (readUInt8(f)<<8) + readUInt8(f);
      skipBytes(f, l-2);
    }
  }

  skipBytes(f, end-fileOffset);
}

void printDefineBitsJpeg(FILE *f, int length)
{
  println("Bitmap id: %i", readUInt16(f));
  printJpegStream(f, length-2);
}

void printDefineBitsJpeg3(FILE *f, int length)
{
  int offset;

  println("Bitmap id: %i", readUInt16(f));

  offset = readUInt32(f);

  printJpegStream(f, offset);

  putchar('\n');
  println("zlib-compressed alpha data:");

  skipBytes(f, length-offset-6);
}

void printDefineBitsLossless(FILE *f, int length)
{
	int format, start = fileOffset;
	int width, height, tablesize, bpp;

	println("Bitmap id: %i", readUInt16(f));

	format = readUInt8(f);
	width = readUInt16(f);
	height = readUInt16(f);

	switch(format)
	{
		case 3:
			tablesize = readUInt8(f)+1;
			bpp = 8;
			break;
		case 4:
			tablesize = readUInt16(f)+1;
			bpp = 16;
			break;
		case 5:
			tablesize = readUInt32(f)+1;
			bpp = 32;
			break;
		default:
			error("unknown bit format: %i", format);
			return;
	}

	println("Format: %d bpp", bpp);
	println("Width: %i", width);
	println("Height: %i", height);
	println("Number of palette entries: %i", tablesize);

#if 0
	println("zlib-compressed image data:");
	{
		unsigned char *data, *buffer;
		long size = width*height;
		long bufsize = start+length-fileOffset;
		int i;
		//int res;

		buffer = malloc(bufsize);

		for(i=0; i<bufsize; ++i)
			buffer[i] = readUInt8(f);

		if(format == 3) size += tablesize*4;
		else size *= 4;

		data = malloc(size);

		/*
		if((res = uncompress(data, &size, buffer, bufsize)) != Z_OK)
			error("Couldn't uncompress bits! (err: %i)\n", res);

		dumpBuffer(data, size);
		*/
	}
#endif

	skipBytes(f, start+length-fileOffset);
	//  dumpBytes(f, start+length-fileOffset);
}

void printDoAction(FILE *f, int length);

static char *dictionary[65536];

int printActionRecord(FILE *f)
{
  int length = 0, type = readUInt8(f);

  if((type&0x80) == 0x80)
    length = readUInt16(f);

  switch(type)
  {
    case SWFACTION_ADD:
      println("Add");
      break;
    case SWFACTION_SUBTRACT:
      println("Subtract");
      break;
    case SWFACTION_MULTIPLY:
      println("Multiply");
      break;
    case SWFACTION_DIVIDE:
      println("Divide");
      break;
    case SWFACTION_EQUAL:
      println("Equals");
      break;
    case SWFACTION_STRICTEQ:
      println("Strictly Equals");
      break;
    case SWFACTION_LESSTHAN:
      println("Less Than");
      break;
    case SWFACTION_LOGICALAND:
      println("And");
      break;
    case SWFACTION_LOGICALOR:
      println("Or");
      break;
    case SWFACTION_LOGICALNOT:
      println("Not");
      break;
    case SWFACTION_STRINGEQ:
      println("String eq");
      break;
    case SWFACTION_STRINGLENGTH:
      println("String Length");
      break;
    case SWFACTION_SUBSTRING:
      println("Substring");
      break;
    case SWFACTION_INT:
      println("Int");
      break;
    case SWFACTION_POP:
      println("Pop");
      break;
    case SWFACTION_SWAP:
      println("Swap");
      break;
    case SWFACTION_INITOBJECT:
      println("Init Object");
      break;
    case SWFACTION_INITARRAY:
      println("Init Array");
      break;
    case SWFACTION_GETVARIABLE:
      println("Get Variable");
      break;
    case SWFACTION_SETVARIABLE:
      println("Set Variable");
      break;
    case SWFACTION_SETTARGETEXPRESSION:
      println("Set Target Expression");
      break;
    case SWFACTION_STRINGCONCAT:
      println("String Concat");
      break;
    case SWFACTION_GETPROPERTY:
      println("Get Property");
      break;
    case SWFACTION_SETPROPERTY:
      println("Set Property");
      break;
    case SWFACTION_DUPLICATECLIP:
      println("Duplicate Clip");
      break;
    case SWFACTION_REMOVECLIP:
      println("Remove Clip");
      break;
    case SWFACTION_TRACE:
      println("Trace");
      break;
    case SWFACTION_STARTDRAGMOVIE:
      println("Start Drag Movie");
      break;
    case SWFACTION_STOPDRAGMOVIE:
      println("Stop Drag Movie");
      break;
    case SWFACTION_STRINGCOMPARE:
      println("String Compare");
      break;
    case SWFACTION_RANDOM:
      println("Random");
      break;
    case SWFACTION_MBLENGTH:
      println("String MB Length");
      break;
    case SWFACTION_ORD:
      println("Ord");
      break;
    case SWFACTION_CHR:
      println("Chr");
      break;
    case SWFACTION_GETTIMER:
      println("Get Timer");
      break;
    case SWFACTION_MBSUBSTRING:
      println("MB Substring");
      break;
    case SWFACTION_MBORD:
      println("MB Ord");
      break;
    case SWFACTION_MBCHR:
      println("MB Chr");
      break;
    case SWFACTION_NEXTFRAME:
      println("Next Frame");
      break;
    case SWFACTION_PREVFRAME:
      println("Previous Frame");
      break;
    case SWFACTION_PLAY:
      println("Play");
      break;
    case SWFACTION_STOP:
      println("Stop");
      break;
    case SWFACTION_TOGGLEQUALITY:
      println("Toggle Quality");
      break;
    case SWFACTION_STOPSOUNDS:
      println("Stop Sounds");
      break;

    /* ops with args */
    case SWFACTION_PUSHDATA:
    {
      int type;
      int start = fileOffset;
      int count = 0;

      print("Push:");
      while(fileOffset < start+length)
      {
	if ( count++ ) putchar(',');
	switch(type = readUInt8(f))
	{
	  case 0: /* string */
	    printf(" string:%s", readString(f));
	    break;
	  case 1: /* property */
	    readUInt16(f); /* always 0? */
	    printf(" property:%04x", readUInt16(f));
	    break;
	  case 2: /* null */
	    printf(" NULL");
	    break;
	  case 3: /* ??? */
	    printf(" type_3:");
	    break;
	  case 4: 
	    printf(" register:%i", readUInt8(f));
	    break;
	  case 5:
	    if(readUInt8(f))
	      printf(" TRUE");
	    else
	      printf(" FALSE");
	    break;
	  case 6: /* double */
	    printf(" double:%f", readDouble(f));
	    break;
	  case 7: /* int */
	    printf(" int:%i", readSInt32(f));
	    break;
	  case 8: /* dictionary */
	    printf(" dict:\"%s\"", dictionary[readUInt8(f)]);
	    break;
	  default:
	    printf(" unknown_type_%i", type);
	}
      }
      putchar('\n');
      break;
    }
    case SWFACTION_GOTOFRAME:
      println("Goto Frame %i", readUInt16(f));
      break;
    case SWFACTION_GETURL:
    {
      char *url = readString(f);
      println("Get URL \"%s\" target \"%s\"", url, readString(f));
      break;
    }
    case SWFACTION_WAITFORFRAMEEXPRESSION:
      println("Wait For Frame Expression, skip %i\n", readUInt8(f));
      break;
    case SWFACTION_BRANCHALWAYS:
      println("Branch Always %i", readSInt16(f));
      break;
    case SWFACTION_GETURL2:
    {
      int flags = readUInt8(f);

      switch(flags)
      {
        case 0: println("Get URL2 (Don't send)"); break;
        case 1: println("Get URL2 (GET)"); break;
        case 2: println("Get URL2 (POST)"); break;
        default: println("GET URL2 (0x%x)", flags);
      }
      break;
    }
    case SWFACTION_BRANCHIFTRUE:
      println("Branch If True %i", readSInt16(f));
      break;
    case SWFACTION_CALLFRAME:
      println("Call Frame");
      dumpBytes(f, length);
      break;
    case SWFACTION_GOTOEXPRESSION:
      print("Goto Expression");
      if(readUInt8(f) == 1)
	printf(" and Play\n");
      else
	printf(" and Stop\n");
      break;
    case SWFACTION_WAITFORFRAME:
    {
      int frame = readUInt16(f);
      println("Wait for frame %i else skip %i", frame, readUInt8(f));
      break;
    }
    case SWFACTION_SETTARGET:
      println("Set Target %s", readString(f));
      break;
    case SWFACTION_GOTOLABEL:
      println("Goto Label %s", readString(f));
      break;
    case SWFACTION_END:
      return 0;
      break;

    /* f5 ops */
    case SWFACTION_DELETE:
      println("Delete");
      break;

    case SWFACTION_DELETEVAR:
      println("Delete2");
      break;

    case SWFACTION_VAR:
      println("Var");
      break;
    case SWFACTION_VAREQUALS:
      println("Var Assign");
      break;
    case SWFACTION_CALLFUNCTION:
      println("Call Function");
      break;
    case SWFACTION_RETURN:
      println("Return");
      break;
    case SWFACTION_MODULO:
      println("Modulo");
      break;
    case SWFACTION_NEW:
      println("New");
      break;
    case SWFACTION_NEWMETHOD:
      println("NewMethod");
      break;
    case SWFACTION_TYPEOF:
      println("Typeof");
      break;
    case SWFACTION_TARGETPATH:
      println("TargetPath");
      break;
    case SWFACTION_NEWADD:
      println("New Add");
      break;
    case SWFACTION_NEWLESSTHAN:
      println("New Less Than");
      break;
    case SWFACTION_NEWEQUAL:
      println("New Equals");
      break;
    case SWFACTION_DUP:
      println("Dup");
      break;
    case SWFACTION_GETMEMBER:
      println("Get Member");
      break;
    case SWFACTION_SETMEMBER:
      println("Set Member");
      break;
    case SWFACTION_INCREMENT:
      println("Increment");
      break;
    case SWFACTION_DECREMENT:
      println("Decrement");
      break;
    case SWFACTION_CALLMETHOD:
      println("Call Method");
      break;
    case SWFACTION_BITWISEAND:
      println("Bitwise And");
      break;
    case SWFACTION_BITWISEOR:
      println("Bitwise Or");
      break;
    case SWFACTION_BITWISEXOR:
      println("Bitwise Xor");
      break;
    case SWFACTION_SHIFTLEFT:
      println("Shift Left");
      break;
    case SWFACTION_SHIFTRIGHT:
      println("Shift Right");
      break;
    case SWFACTION_SHIFTRIGHT2:
      println("Shift Right 2");
      break;

    case SWFACTION_DECLARENAMES:
    {
      int i, n = readUInt16(f);
      print("Declare Dictionary:");

      for(i=0; i<n; ++i)
	printf(" %s%c", dictionary[i]=readString(f), (i<n-1)?',':'\n');

      break;
    }
    case SWFACTION_WITH:
    {
      println("With");

      ++gIndent;
      printDoAction(f, readUInt16(f));
      --gIndent;

      break;
    }
    case SWFACTION_DEFINEFUNCTION:
    {
      char *name = readString(f);
      int n = readUInt16(f);

      print("function %s(", name);

      if(n>0)
      {
	printf("%s", readString(f));
	--n;
      }

      for(; n>0; --n)
	printf(", %s", readString(f));

      putchar(')');
      putchar('\n');

      ++gIndent;
      printDoAction(f, readUInt16(f));
      --gIndent;

      break;
    }

    case SWFACTION_ENUMERATE:
      println("Enumerate");
      break;

    case SWFACTION_SETREGISTER:
      println("Set Register %i", readUInt8(f));
      break;

    default:
      println("Unknown Action: %02X", type);
      dumpBytes(f, length);
  }
  return 1;
}

#ifndef NODECOMPILE
void printDecompiledAction(FILE *f, int l, int n)
{
	char *as = decompile5Action(f, l, n);
	puts(as);
}
#endif

void printDoAction(FILE *f, int length)
{
  int start = fileOffset, end = fileOffset+length;

  while(fileOffset<end)
  {
    printf("%i\t", fileOffset-start);
    if(!printActionRecord(f))
      break;
  }
}

int printButtonRecord(FILE *f, int recordType)
{
  int character, layer;
  int flags = readUInt8(f);

  if(flags == 0)
    return 0;

  if(flags & 0x08)
    println("Hit flag: ");
  if(flags & 0x04)
    println("Down flag: ");
  if(flags & 0x02)
    println("Over flag: ");
  if(flags & 0x01)
    println("Up flag: ");

  character = readUInt16(f);
  layer = readUInt16(f);

  println("character: %i, layer %i", character, layer);
  printMatrix(f);

  if(recordType == 2)
    printCXForm(f, true); /* XXX - should be true? */

  return 1;
}

void printDefineButton(FILE *f, int length)
{
  int offset = fileOffset;

  println("Button id: %i", readUInt16(f));

  ++gIndent;
  while(printButtonRecord(f, 1)) ;

  decompileAction(f, length-(fileOffset-offset), 0);
  --gIndent;
}

int printButton2ActionCondition(FILE *f, int end)
{
  int offset = readUInt16(f);
  int condition = readUInt16(f);

  println("offset = %i", offset);

  if(condition & 0xfe00) println("condition: keyPress(%c)", (condition&0xfe00)>>9);
  if(condition & 0x100) println("condition: overDownToIdle");
  if(condition & 0x80)  println("condition: idleToOverDown");
  if(condition & 0x40)  println("condition: outDownToIdle");
  if(condition & 0x20)  println("condition: outDownToOverDown");
  if(condition & 0x10)  println("condition: overDownToOutDown");
  if(condition & 0x08)  println("condition: overDownToOverUp");
  if(condition & 0x04)  println("condition: overUpToOverDown");
  if(condition & 0x02)  println("condition: overUpToIdle");
  if(condition & 0x01)  println("condition: idleToOverUp");

  if(offset == 0)
    decompileAction(f, end-fileOffset, 0);
  else
    decompileAction(f, offset-4, 0);

  return offset;
}

void printDefineButton2(FILE *f, int length)
{
  int flags, offset, end = fileOffset+length;

  println("Button id: %i", readUInt16(f));
  flags = readUInt8(f); /* flags */

  if(flags)
    println("tracked as menu item (whatever that means..)");

  offset = readUInt16(f); /* offset */
  println("offset = %i", offset);

  while(printButtonRecord(f, 2)) ;

  if(offset>0)
    while(printButton2ActionCondition(f, end)) ;
}

void printPlaceObject(FILE *f, int length)
{
  int start = fileOffset;

  println("Character ID: %i", readUInt16(f));
  println("Depth: %i", readUInt16(f));
  println("Matrix:");
  printMatrix(f);

  if(fileOffset < start+length)
  {
    print("CXform: ");
    printCXForm(f, false);
    putchar('\n');
  }
}

#define PLACE_RESERVED		(1<<7)
#define PLACE_HASCLIP		(1<<6)
#define PLACE_HASNAME		(1<<5)
#define PLACE_HASRATIO		(1<<4)
#define PLACE_HASCXFORM		(1<<3)
#define PLACE_HASMATRIX		(1<<2)
#define PLACE_HASCHARACTER	(1<<1)
#define PLACE_HASMOVE		(1<<0)

void printPlaceObject2(FILE *f, int length)
{
  int start = fileOffset;
  int flags = readUInt8(f);
  int l;

  println("Depth: %i", readUInt16(f));

  if(flags & PLACE_HASMOVE)
    println("Has move flag");

  if(flags & PLACE_HASCHARACTER)
    println("Character ID: %i", readUInt16(f));

  if(flags & PLACE_HASMATRIX)
  {
    println("Matrix:");
    printMatrix(f);
  }

  if(flags & PLACE_HASCXFORM)
  {
    print("CXForm: ");
    printCXForm(f, true);
    putchar('\n');
  }

  if(flags & PLACE_HASRATIO)
    println("Ratio: %i", readUInt16(f));

  if(flags & PLACE_HASNAME)
    println("Name: %s", readString(f));

  if(flags & PLACE_HASCLIP)
    println("ClipDepth: %i", readUInt16(f));

  if(flags & PLACE_RESERVED)
  {
    println("Mystery number: %04x", readUInt16(f));

    flags = readUInt16(f);
    println("Clip flags: %04x", flags);

    while((flags = readUInt16(f)) != 0)
    {
      println("Flags: %04x", flags);
      l = readUInt32(f);
      decompileAction(f, l, 0);
    }
  }

  dumpBytes(f, length-(fileOffset-start));
}

void printRemoveObject(FILE *f)
{
  println("ID: %i", readUInt16(f));
  println("Depth: %i", readUInt16(f));
}

void printRemoveObject2(FILE *f)
{
  println("Depth: %i", readUInt16(f));
}

void printSetBackgroundColor(FILE *f)
{
  print("Color: ");
  printRGB(f);
  putchar('\n');
}

void printFrameLabel(FILE *f)
{
  println("Label: %s\n", readString(f));
}

void printDefineFont(FILE *f, int length)
{
  int here, off0, off, i, nShapes, fillBits=1, lineBits=1;
  int *offset;

  println("FontID: %i", readUInt16(f));

  off0 = readUInt16(f);

  nShapes = off0/2;
  println("Number of shapes: %i", nShapes);

  offset = (int *)malloc(nShapes*sizeof(int));

  ++gIndent;
  println("Offset0: 0");

  for(i=1; i<nShapes; ++i)
  {
    off = readUInt16(f);
    offset[i-1] = off-off0;
    println("Offset%i: %i", i, offset[i-1]);
  }
  offset[nShapes-1] = length-2-(nShapes*2);

  here = fileOffset;

  for(i=0; i<nShapes; ++i)
  {
    putchar('\n');

    byteAlign();
    println("Shape %i:", i);

    fillBits = readBits(f, 4);
    lineBits = readBits(f, 4);

    ++gIndent;
    while(fileOffset < here+offset[i])
      printShapeRec(f, &fillBits, &lineBits, 2);
    --gIndent;
  }

  --gIndent;
}

#define FONTINFO2_HASLAYOUT		(1<<7)
#define FONTINFO2_SHIFTJIS		(1<<6)
#define FONTINFO2_UNICODE		(1<<5)
#define FONTINFO2_ANSI			(1<<4)
#define FONTINFO2_WIDEOFFSETS	        (1<<3)
#define FONTINFO2_WIDECODES		(1<<2)
#define FONTINFO2_ITALIC		(1<<1)
#define FONTINFO2_BOLD			(1<<0)

void printDefineFont2(FILE *f, int length)
{
  int flags, nGlyphs, namelen, i, fillBits, lineBits;
  int here = fileOffset;
  int *offset;

  println("fontID: %i", readUInt16(f));

  flags = readUInt8(f);

  readUInt8(f); /* "reserved" */

  namelen = readUInt8(f);

  print("Font Name: ");

  for(; namelen>0; --namelen)
    putchar((unsigned char)readUInt8(f));

  putchar('\n');

  nGlyphs = readUInt16(f);
  println("number of glyphs: %i\n", nGlyphs);

  offset = (unsigned int *)malloc(nGlyphs*sizeof(int));

  /* offset table */

  here = fileOffset;

  for(i=0; i<=nGlyphs; ++i)
  {
    if(flags & FONTINFO2_WIDEOFFSETS)
      offset[i] = readUInt32(f)-4*nGlyphs-2;
    else
      offset[i] = readUInt16(f)-2*nGlyphs-2;

    println("Offset%i: %i", i, offset[i]);
  }

  here = fileOffset;

  /* shape table */
  for(i=0; i<nGlyphs; ++i)
  {
    byteAlign();
    println("Glyph %i:", i);

    fillBits = readBits(f, 4);
    lineBits = readBits(f, 4);

    byteAlign();
    while(printShapeRec(f, &fillBits, &lineBits, 2)) ;

    putchar('\n');
  }

  /* code table */
  for(i=0; i<nGlyphs; ++i)
  {
    if(flags & FONTINFO2_WIDECODES)
      println("glyph code %i: %i", i, readUInt16(f));
    else
      println("glyph code %i: %i", i, readUInt8(f));
  }

  if(flags & FONTINFO2_HASLAYOUT)
  {
    int kernCount, code1, code2;

    println("ascender height: %i", readSInt16(f));
    println("descender height: %i", readSInt16(f));
    println("leading height: %i", readSInt16(f));

    for(i=0; i<nGlyphs; ++i)
      printf("\tadvance %i: %i\n", i, readSInt16(f));

    for(i=0; i<nGlyphs; ++i)
    {
      print("bounds %i: ", i);
      printRect(f);
      putchar('\n');
    }

    kernCount = readUInt16(f);

    for(i=0; i<kernCount; ++i)
    {
      code1 = (flags & FONTINFO2_WIDECODES) ? readUInt16(f) : readUInt8(f);
      code2 = (flags & FONTINFO2_WIDECODES) ? readUInt16(f) : readUInt8(f);
      println("(%i,%i): adjustment = %i", code1, code2, readSInt16(f));
    }
  }
}

#define FONTINFO_RESERVED	(1<<6 | 1<<7)
#define FONTINFO_UNICODE	(1<<5)
#define FONTINFO_SHIFTJIS	(1<<4)
#define FONTINFO_ANSI		(1<<3)
#define FONTINFO_ITALIC		(1<<2)
#define FONTINFO_BOLD		(1<<1)
#define FONTINFO_WIDE		(1<<0)

void printFontInfo(FILE *f, int length)
{
  int namelen, nGlyphs, flags, i;

  println("FontID: %i", readUInt16(f));

  namelen = readUInt8(f);
  nGlyphs = length-namelen-4;

  print("Font Name: ");

  for(; namelen>0; --namelen)
    putchar((unsigned char)readUInt8(f));

  putchar('\n');

  flags = readUInt8(f);

  if(flags & FONTINFO_UNICODE)
    println("Unicode character codes!");

  if(flags & FONTINFO_SHIFTJIS)
    println("\tShiftJIS character codes!");

  if(flags & FONTINFO_ANSI)
    println("\tANSI character codes!");

  if(flags & FONTINFO_ITALIC)
    println("\tFont is italic!");

  if(flags & FONTINFO_BOLD)
    println("\tFont is bold!");

  if(flags & FONTINFO_WIDE)
    nGlyphs /= 2;

  for(i=0; i<nGlyphs; ++i)
    if(flags & FONTINFO_WIDE)
      println("glyph %i: %i", i, readUInt16(f));
    else
      println("glyph %i: %i", i, readUInt8(f));
}

#define TEXTRECORD_STATECHANGE	(1<<7)
#define TEXTRECORD_RESERVED		(1<<6 | 1<<5 | 1<<4)
#define TEXTRECORD_HASFONT		(1<<3)
#define TEXTRECORD_HASCOLOR		(1<<2)
#define TEXTRECORD_HASYOFF		(1<<1)
#define TEXTRECORD_HASXOFF		(1<<0)
#define TEXTRECORD_NUMGLYPHS	0x7f

int printTextRecord(FILE *f, int glyphBits, int advanceBits, int type)
{
  int i, numGlyphs;
  int flags = readUInt8(f);

  if(flags == 0)
    return 0;

  if(flags & TEXTRECORD_STATECHANGE)
  {
    if(flags & TEXTRECORD_HASFONT)
      println("font id: %i", readUInt16(f));

    if(flags & TEXTRECORD_HASCOLOR)
    {
      print("color: ");

      if(type == 2)
	printRGBA(f);
      else
	printRGB(f);

      putchar('\n');
    }

    if(flags & TEXTRECORD_HASXOFF)
      println("X Offset: %i", readSInt16(f));

    if(flags & TEXTRECORD_HASYOFF)
      println("Y Offset: %i", readSInt16(f));

    if(flags & TEXTRECORD_HASFONT)
      println("font height: %i", readUInt16(f));
  }
  else
  {
    numGlyphs = flags & TEXTRECORD_NUMGLYPHS;

    for(i=0; i<numGlyphs; ++i)
    {
      println("glyph index: %i", readBits(f, glyphBits));
      println("glyph x advance: %i", readSBits(f, advanceBits));
    }
  }

  return 1;
}

void printDefineText(FILE *f, int length, int type) /* type 2 allows transparency */
{
  int glyphBits, advanceBits, end = fileOffset+length;

  println("character id: %i", readUInt16(f));
  print("bounds: ");
  printRect(f);
  putchar('\n');
  byteAlign();
  println("matrix:");
  printMatrix(f);
  glyphBits = readUInt8(f);
  advanceBits = readUInt8(f);

  while(fileOffset < end &&
	printTextRecord(f, glyphBits, advanceBits, type)) ;
}

void printSoundInfo(FILE *f)
{
  int flags = readUInt8(f), nPoints, i;

  ++gIndent;

  if(flags&0x40)
    println("Don't start if already playing");

  if(flags&0x80)
    println("Stop sound");

  if(flags&0x01)
    println("In Point: %i", readUInt32(f));

  if(flags&0x02)
    println("Out Point: %i", readUInt32(f));

  if(flags&0x04)
    println("Loops: %i", readUInt16(f));

  if(flags&0x08)
  {
    nPoints = readUInt8(f);
    for(i=0; i<nPoints; ++i)
    {
      println("Envelope point %i:", i);
      println("Mark44: %i", readUInt32(f));
      println("Level0: %i", readUInt16(f));
      println("Level1: %i", readUInt16(f));
    }
  }

  --gIndent;
}


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
int mp25_samplerate_table[] = { 11025, 12000, 8000 }; /* less samples in > versions? */

#define MP3_PADDING          0x00000200 /* if set, add an extra slot - 4 bytes
					   for layer 1, 1 byte for 2+3 */

#define MP3_CHANNEL          0x000000C0
#define MP3_CHANNEL_STEREO   0x00000000
#define MP3_CHANNEL_JOINT    0x00000040
#define MP3_CHANNEL_DUAL     0x00000080
#define MP3_CHANNEL_MONO     0x000000C0

/* rest of the header info doesn't affect frame size.. */

void silentSkipBytes(FILE *f, int length)
{
  for(; length>0; --length)
    readUInt8(f);
}

void printMP3Headers(FILE *f, int length)
{
  unsigned long flags;
  int frameLen, frameNum = 0;
  int bitrate, bitrate_idx, samplerate, samplerate_idx;
  int version, layer, channels;
  int padding;

  while(length > 0)
  {
    ++frameNum;

    /* get 4-byte header, bigendian */
    flags = fgetc(f) << 24;
    flags += fgetc(f) << 16;
    flags += fgetc(f) << 8;
    flags += fgetc(f);

    fileOffset += 4;

    if((flags & MP3_FRAME_SYNC) != MP3_FRAME_SYNC)
      error("bad sync on MP3 block!");

    bitrate_idx = (flags & MP3_BITRATE) >> MP3_BITRATE_SHIFT;
    samplerate_idx = (flags & MP3_SAMPLERATE) >> MP3_SAMPLERATE_SHIFT;

    channels = ((flags & MP3_CHANNEL) == MP3_CHANNEL_MONO) ? 1 : 2;

    switch(flags & MP3_VERSION)
    {
      case MP3_VERSION_1:  version = 1; break;
      case MP3_VERSION_2:  version = 2; break;
      case MP3_VERSION_25: version = 25; break;
      default: error("unknown MP3 version!"); return;
    }
    switch(flags & MP3_LAYER)
    {
      case MP3_LAYER_1: layer = 1; break;
      case MP3_LAYER_2: layer = 2; break;
      case MP3_LAYER_3: layer = 3; break;
      default: error("unknown MP3 layer!"); return;
    }

    if(version == 1)
    {
      samplerate = mp1_samplerate_table[samplerate_idx];

      if(layer == 1)
	bitrate = mp1l1_bitrate_table[bitrate_idx];

      else if(layer == 2)
	bitrate = mp1l2_bitrate_table[bitrate_idx];

      else // if(layer == 3)
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

    println("frame %i: MP%i layer %i, %i Hz, %ikbps, %s, length=%i, protect %s",
	   frameNum, version, layer, samplerate, bitrate,
	   (channels==2) ? "stereo" : "mono", frameLen,
	   (flags&MP3_PROTECT) ? "on" : "off");

    if(length < frameLen-4)
      silentSkipBytes(f, length);
    else
      silentSkipBytes(f, frameLen-4);

    length -= frameLen;
  }

  if(length>0)
    dumpBytes(f, length);
}

void printDefineSound(FILE *f, int length)
{
  int flags;

  println("Character ID: %i", readUInt16(f));

  flags = readUInt8(f);

  switch(flags&0xf0)
  {
    case 0x20: print("Sound Format: mp3 ");              break;
    case 0x10: print("Sound Format: ADPCM compressed "); break;
    case 0x00: print("Sound Format: uncompressed ");     break;
    default:   print("Sound Format: unknown compression ");
  }

  if((flags&0x0c) == 0)
    puts("5KHz ");
  else if((flags&0x0c) == 4)
    puts("11KHz ");
  else if((flags&0x0c) == 8)
    puts("22KHz ");
  else
    puts("44KHz ");

  if(flags&0x02)
    puts("16 bit ");
  else
    puts("8 bit ");

  if(flags&0x01)
    puts("stereo\n");
  else
    puts("mono\n");

  println("Number of samples: %i", readUInt32(f));

  if((flags&0xf0) == 0x20) /* mp3 */
  {
    ++gIndent;
    println("Delay: %i", readUInt16(f));
    printMP3Headers(f, length-9);
    --gIndent;
  }
  else
    dumpBytes(f, length-7);
}

int streamflags;

/* only difference is type 2 allows uncompressed data,
   and 8-bit if uncompressed */
void printSoundStreamHead(FILE *f, int type)
{
  int recFormat = readUInt8(f);
  int flags = readUInt8(f);

  streamflags = flags;

  println("Recommended Format: %02x", recFormat);
  println("flags: %02x", flags);

  if((flags&0xf0) == 0x20)
  {
    println("mp3 format");
    println("Avg. number of Samples per Block: %i", readUInt16(f));
    println("Mystery goo: %i", readUInt16(f));
  }
  else
    println("Number of Samples: %i", readUInt16(f));
}

void printSoundStreamBlock(FILE *f, int length)
{
  int samplesperframe, delay;

  if((streamflags&0xf0) == 0x00)
  {
    println("Uncompressed samples");
    skipBytes(f, length);
  }
  else if((streamflags&0xf0) == 0x10)
  {
    println("ADPCM compressed samples");
    skipBytes(f, length);
  }
  else if((streamflags&0xf0) == 0x20)
  {
    samplesperframe = readUInt16(f);
    delay = readUInt16(f);
    println("MP3 compressed samples: %i samples, delay=%i",
	    samplesperframe, delay);

    printMP3Headers(f, length-4);
  }
  else
    println("Unknown compression type!");
}

void printSprite(FILE *f, int length)
{
  int start = fileOffset;
  int block, type, l;

  println("id: %i", readUInt16(f));
  println("frame count: %i\n", readUInt16(f));

  while(fileOffset < start+length)
  {
    println("Offset %i (0x%x)", fileOffset, fileOffset);

    block = readUInt16(f);
    type = block>>6;

    println("Block type: %i (%s)", type, blockName(type));

    l = block & ((1<<6)-1);

    if(l == 63) /* it's a long block. */
      l = readUInt32(f);

    println("Block length: %i\n", l);

    ++gIndent;

    switch(type)
    {
      case SWF_PLACEOBJECT:		printPlaceObject(f, l);		break;
      case SWF_PLACEOBJECT2:		printPlaceObject2(f, l);	break;
      case SWF_REMOVEOBJECT:		printRemoveObject(f);		break;
      case SWF_REMOVEOBJECT2:		printRemoveObject2(f);		break;
      case SWF_FRAMELABEL:		printFrameLabel(f);		break;
      case SWF_DOACTION:		decompileAction(f, l, 0);       break;
      case SWF_SOUNDSTREAMHEAD: 	printSoundStreamHead(f, 1);     break;
      case SWF_SOUNDSTREAMHEAD2:	printSoundStreamHead(f, 2);     break;
      case SWF_SOUNDSTREAMBLOCK:	printSoundStreamBlock(f, l);    break;
      default:			if(l>0) dumpBytes(f, l);		break;
    }

    --gIndent;
  /*
    startsound
  */
  }
}

#define TEXTFIELD_HASLENGTH (1<<1)
#define TEXTFIELD_NOEDIT    (1<<3)
#define TEXTFIELD_PASSWORD  (1<<4)
#define TEXTFIELD_MULTILINE (1<<5)
#define TEXTFIELD_WORDWRAP  (1<<6)
#define TEXTFIELD_DRAWBOX   (1<<11)
#define TEXTFIELD_NOSELECT  (1<<12)

#define TEXTFIELD_JUSTIFY_LEFT    0
#define TEXTFIELD_JUSTIFY_RIGHT   1
#define TEXTFIELD_JUSTIFY_CENTER  2
#define TEXTFIELD_JUSTIFY_JUSTIFY 3

void printTextField(FILE *f, int length)
{
  int flags, num, end = fileOffset+length;

  println("Character id: %i", readUInt16(f));
  print("Bounds: ");
  printRect(f);
  println("flags: 0x%04x", flags=readUInt16(f));

  if(flags & TEXTFIELD_HASLENGTH)
    println("Has Length");
  if(flags & TEXTFIELD_NOEDIT)
    println("Disable Editing");
  if(flags & TEXTFIELD_PASSWORD)
    println("Password Field");
  if(flags & TEXTFIELD_MULTILINE)
    println("Multiline");
  if(flags & TEXTFIELD_WORDWRAP)
    println("Word Wrap");
  if(flags & TEXTFIELD_DRAWBOX)
    println("Draw Bounding Box");
  if(flags & TEXTFIELD_NOSELECT)
    println("No Select");

  println("Font id: %i", readUInt16(f));
  println("Font height: %i", readUInt16(f));
  print("Color: ");
  printRGBA(f);
  putchar('\n');

  if(flags & TEXTFIELD_HASLENGTH)
    println("Length (max chars): %i", readUInt16(f));

  print("Alignment: ");

  switch(num = readUInt8(f))
  {
    case TEXTFIELD_JUSTIFY_LEFT:    print("left\n");    break;
    case TEXTFIELD_JUSTIFY_RIGHT:   print("right\n");   break;
    case TEXTFIELD_JUSTIFY_CENTER:  print("center\n");  break;
    case TEXTFIELD_JUSTIFY_JUSTIFY: print("justify\n"); break;
    default: println("unexpected justification: %i", num);
  }

  println("Left margin: %i", readUInt16(f));
  println("Right margin: %i", readUInt16(f));
  println("First line indentation: %i", readUInt16(f));
  println("Line spacing: %i", readUInt16(f));

  println("Variable Name: %s", readString(f));

  if(fileOffset<end)
    println("Initial Text: %s", readString(f));

  putchar('\n');

  if(fileOffset<end)
    dumpBytes(f, end-fileOffset);
}

void printLibrarySymbol(FILE *f, int length)
{
  println("mystery number: %i", readUInt16(f));
  println("character id: %i", readUInt16(f));
  println("name: %s", readString(f));
}

void printPassword(FILE *f, int length)
{
  println("mystery number: %i", readUInt16(f));
  println("encrypted password: %s", readString(f));
}

void skipBytes(FILE *f, int length)
{
  ++gIndent;
  println("<%i bytes skipped>", length);
  --gIndent;

  for(; length>0; --length)
    readUInt8(f);
}

void printImportAssets(FILE *f, int length)
{
      int n, i;
      println("\tAsset URL: %s", readString(f));
      n = readUInt16(f);
      println("\tNumber of assets: %d", n);
      for (i=0; i<n; i++)
      {
      	print("\tTag%d: %d\n", i+1, readUInt16(f));
      	print("\tName%d: %s\n", i+1, readString(f));
      }
}

int main(int argc, char *argv[])
{
  FILE *f;
  int size, version, block, type, length;

  if(argc > 1)
  {
    if(!(f = fopen(argv[1],"rb")))
      error("Sorry, can't seem to read that file.\n");
  }
  else
    f = stdin;

  while(!feof(f))
  {
    if(fgetc(f)=='F' && fgetc(f)=='W' && fgetc(f)=='S')
      break;
  }

  if(feof(f))
    error("Doesn't look like a swf file to me..\n");

  fileOffset = 3;

  version = readUInt8(f);

  size = readUInt32(f);

  println("File size: %i", size);

  print("Frame size: ");
  printRect(f);
  putchar('\n');

  println("Frame rate: %f / sec.", readUInt8(f)/256.0+readUInt8(f));

  println("Total frames: %i", readUInt16(f));
  putchar('\n');

  for(;;)
  {
    println("Offset: %i (0x%06x)", fileOffset, fileOffset);

    block = readUInt16(f);
    type = block>>6;

    println("Block type: %i (%s)", type, blockName(type));

    length = block & ((1<<6)-1);

    if(length == 63) /* it's a long block. */
      length = readUInt32(f);

    println("Block length: %i", length);
    putchar('\n');

    if(type == 0 || fileOffset >= size || length < 0)
      break;

    ++gIndent;

    switch(type)
    {
      case SWF_DEFINESPRITE:        printSprite(f, length);         break;
      case SWF_DEFINESHAPE3:
      case SWF_DEFINESHAPE2:
      case SWF_DEFINESHAPE:         printShape(f, length, type);	break;
      case SWF_PLACEOBJECT:		printPlaceObject(f, length);	break;
      case SWF_PLACEOBJECT2:	printPlaceObject2(f, length);	break;
      case SWF_REMOVEOBJECT:	printRemoveObject(f);		break;
      case SWF_REMOVEOBJECT2:	printRemoveObject2(f);		break;
      case SWF_SETBACKGROUNDCOLOR:	printSetBackgroundColor(f);	break;
      case SWF_FRAMELABEL:		printFrameLabel(f);		break;
      case SWF_DEFINEMORPHSHAPE:	printMorphShape(f, length);	break; 
      case SWF_DEFINEFONT:		printDefineFont(f, length);	break;
      case SWF_DEFINEFONT2:		printDefineFont2(f, length);	break;
      case SWF_DEFINEFONTINFO:	printFontInfo(f, length);	break;
      case SWF_DEFINETEXT:		printDefineText(f, length, 1);	break;
      case SWF_DEFINETEXT2:		printDefineText(f, length, 2);	break;
      case SWF_DOACTION:		decompileAction(f, length, 0);	break;
      case SWF_DEFINESOUND:         printDefineSound(f, length);    break;
      case SWF_SOUNDSTREAMHEAD:     printSoundStreamHead(f, 1);     break;
      case SWF_SOUNDSTREAMHEAD2:    printSoundStreamHead(f, 2);     break;
      case SWF_SOUNDSTREAMBLOCK:    printSoundStreamBlock(f, length); break;
      case SWF_DEFINEBUTTON:        printDefineButton(f, length);   break;
      case SWF_DEFINEBUTTON2:       printDefineButton2(f, length);  break;
      case SWF_JPEGTABLES:          printJpegStream(f, length);     break;
      case SWF_DEFINEBITS:
      case SWF_DEFINEBITSJPEG2:     printDefineBitsJpeg(f,length);  break;
      case SWF_DEFINEBITSJPEG3:     printDefineBitsJpeg3(f,length); break;
      case SWF_DEFINELOSSLESS:
      case SWF_DEFINELOSSLESS2:	printDefineBitsLossless(f,length); break;
      case SWF_DEFINEEDITTEXT:	printTextField(f, length);	break;
      case SWF_EXPORTASSETS:	printLibrarySymbol(f, length);	break;
      case SWF_ENABLEDEBUGGER:	printPassword(f, length);	break;
      case SWF_IMPORTASSETS:	printImportAssets(f, length);   break;

      default:                  dumpBytes(f, length);	        break;
    }

    --gIndent;
    putchar('\n');
  }

  dumpBytes(f, size-fileOffset);

  return 0;
}
