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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "blocks/blocktypes.h"
#include "abctypes.h"
#include "action.h"
#include "decompile.h"
#include "parser.h"
#include "read.h"
#include "blocks/error.h"

extern struct Movie m;
extern SWF_Parserstruct *blockParse (FILE *f, int length, SWFBlocktype header);
const char *blockName (SWFBlocktype header);
void silentSkipBytes(FILE *f, int length);

#define PAR_BEGIN(block) 						\
	struct block *parserrec; 					\
	SWF_Parserstruct *pstruct; 					\
	pstruct = calloc(1, sizeof(SWF_Parserstruct)); 			\
	pstruct->length = length;					\
	pstruct->offset = fileOffset - ( (length >= 63 ) ? 6 : 2) ;	\
	parserrec= (struct block *)pstruct; 				\

#define PAR_END \
	return (SWF_Parserstruct *)parserrec;

#define SKIP \
	printf("skipping %i bytes\n", length); \
        readBytes(f, length);

/* Parse Basic Flash types */

void
parseSWF_RGB (FILE * f, struct SWF_RGBA *rgb)
{
  rgb->red = readUInt8 (f);
  rgb->green = readUInt8 (f);
  rgb->blue = readUInt8 (f);
  rgb->alpha = 255;
}

void
parseSWF_RGBA (FILE * f, struct SWF_RGBA *rgb)
{
  rgb->red = readUInt8 (f);
  rgb->green = readUInt8 (f);
  rgb->blue = readUInt8 (f);
  rgb->alpha = readUInt8 (f);
}

void
parseSWF_RECT (FILE * f, struct SWF_RECT *rect)
{
  byteAlign ();

  rect->Nbits = readBits (f, 5);
  rect->Xmin = readSBits (f, rect->Nbits);
  rect->Xmax = readSBits (f, rect->Nbits);
  rect->Ymin = readSBits (f, rect->Nbits);
  rect->Ymax = readSBits (f, rect->Nbits);
}

void
parseSWF_MATRIX (FILE * f, struct SWF_MATRIX *matrix)
{
  byteAlign ();

  matrix->HasScale = readBits (f, 1);
  if (matrix->HasScale)
    {
      matrix->NScaleBits = readBits (f, 5);
      matrix->ScaleX = (float) readSBits (f, matrix->NScaleBits) / 0x10000;
      matrix->ScaleY = (float) readSBits (f, matrix->NScaleBits) / 0x10000;
    }
  matrix->HasRotate = readBits (f, 1);
  if (matrix->HasRotate)
    {
      matrix->NRotateBits = readBits (f, 5);
      matrix->RotateSkew0 =
	(float) readSBits (f, matrix->NRotateBits) / 0x10000;
      matrix->RotateSkew1 =
	(float) readSBits (f, matrix->NRotateBits) / 0x10000;
    }
  matrix->NTranslateBits = readBits (f, 5);
  matrix->TranslateX = readSBits (f, matrix->NTranslateBits);
  matrix->TranslateY = readSBits (f, matrix->NTranslateBits);
  byteAlign();
}

void 
parseSWF_FILTERLIST(FILE *f, SWF_FILTERLIST *list);

int
parseSWF_BUTTONRECORD (FILE * f, struct SWF_BUTTONRECORD *brec, int level)
{
  byteAlign ();

  brec->ButtonReserved = readBits (f, 2);
  brec->ButtonHasBlendMode = readBits(f, 1);
  brec->ButtonHasFilterList = readBits(f, 1);
  brec->ButtonStateHitTest = readBits (f, 1);
  brec->ButtonStateDown = readBits (f, 1);
  brec->ButtonStateOver = readBits (f, 1);
  brec->ButtonStateUp = readBits (f, 1);
  if( brec->ButtonStateHitTest == 0 &&
      brec->ButtonStateDown == 0 &&
      brec->ButtonStateOver == 0 &&
      brec->ButtonStateUp == 0 &&
      brec->ButtonHasBlendMode == 0 && 
      brec->ButtonHasFilterList == 0 &&
      brec->ButtonReserved == 0)
	  return 0;  // CharacterEndFlag 
  brec->CharacterId = readUInt16 (f);
  brec->PlaceDepth = readUInt16 (f);
  parseSWF_MATRIX (f, &brec->PlaceMatrix);
  if( level > 1 )
  	parseSWF_CXFORMWITHALPHA (f, &brec->ColorTransform);
  if ( brec->ButtonHasFilterList )
	parseSWF_FILTERLIST(f, &brec->FilterList);
  if ( brec->ButtonHasBlendMode )
	brec->BlendMode = readUInt8(f);
  return 1;
}

int
parseSWF_BUTTONCONDACTION (FILE * f, struct SWF_BUTTONCONDACTION *bcarec, int end)
{
  int actionEnd, start;
  byteAlign ();

  start = fileOffset;
  bcarec->CondActionSize = readUInt16 (f);
  bcarec->CondIdleToOverDown = readBits (f, 1);
  bcarec->CondOutDownToIdle = readBits (f, 1);
  bcarec->CondOutDownToOverDown = readBits (f, 1);
  bcarec->CondOverDownToOutDown = readBits (f, 1);
  bcarec->CondOverDownToOverUp = readBits (f, 1);
  bcarec->CondOverUpToOverDown = readBits (f, 1);
  bcarec->CondOverUpToIdle = readBits (f, 1);
  bcarec->CondIdleToOverUp = readBits (f, 1);
  bcarec->CondKeyPress = readBits (f, 7);
  bcarec->CondOverDownToIdle = readBits (f, 1);

  bcarec->Actions =
    (SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
  bcarec->numActions = 0;
  while ( parseSWF_ACTIONRECORD (f, &(bcarec->numActions), bcarec->Actions) ) {
      bcarec->Actions = (SWF_ACTION *) realloc (bcarec->Actions,
							 (++bcarec->
							  numActions +
							  1) *
							 sizeof
							 (SWF_ACTION));
    }

  if(bcarec->CondActionSize > 0)
	actionEnd = start + bcarec->CondActionSize;
  else
	actionEnd = end;

  if(fileOffset >= actionEnd)
  {
	SWF_warn("parseSWF_BUTTONCONDACTION: expected actionEnd flag\n");
  	return bcarec->CondActionSize;
  }

  /* read end action flag only there are realy action records
   * if there are no actionrecords parseSWF_ACTIONRECORD did already
   * read end action
   */
  if(bcarec->numActions > 0)
    readUInt8(f);
  return bcarec->CondActionSize;
}

void
parseSWF_CXFORM (FILE * f, struct SWF_CXFORM *cxform)
{
  byteAlign ();

  cxform->HasAddTerms = readBits (f, 1);
  cxform->HasMultTerms = readBits (f, 1);
  cxform->Nbits = readBits (f, 4);
  if( cxform->HasMultTerms ) {
    cxform->RedMultTerm = readSBits(f, cxform->Nbits );
    cxform->GreenMultTerm = readSBits(f, cxform->Nbits );
    cxform->BlueMultTerm = readSBits(f, cxform->Nbits );
  }
  if( cxform->HasAddTerms ) {
    cxform->RedAddTerm = readSBits(f, cxform->Nbits );
    cxform->GreenAddTerm = readSBits(f, cxform->Nbits );
    cxform->BlueAddTerm = readSBits(f, cxform->Nbits );
  }
}

void
parseSWF_CXFORMWITHALPHA (FILE * f, struct SWF_CXFORMWITHALPHA *cxform)
{
  byteAlign ();

  cxform->HasAddTerms = readBits (f, 1);
  cxform->HasMultTerms = readBits (f, 1);
  cxform->Nbits = readBits (f, 4);
  if( cxform->HasMultTerms ) {
    cxform->RedMultTerm = readSBits(f, cxform->Nbits );
    cxform->GreenMultTerm = readSBits(f, cxform->Nbits );
    cxform->BlueMultTerm = readSBits(f, cxform->Nbits );
    cxform->AlphaMultTerm = readSBits(f, cxform->Nbits );
  }
  if( cxform->HasAddTerms ) {
    cxform->RedAddTerm = readSBits(f, cxform->Nbits );
    cxform->GreenAddTerm = readSBits(f, cxform->Nbits );
    cxform->BlueAddTerm = readSBits(f, cxform->Nbits );
    cxform->AlphaAddTerm = readSBits(f, cxform->Nbits );
  }
}

void
parseSWF_GLYPHENTRY (FILE * f, SWF_GLYPHENTRY *gerec, int glyphbits, int advancebits)
{
  int i;

  size_t nmalloc = ( glyphbits < 1 ? 1 : ((glyphbits+31)/32) ) * sizeof(UI32);
  gerec->GlyphIndex = malloc(nmalloc);
  gerec->GlyphIndex[0] = 0; /* for glyphbits == 0 */
  for( i=0; glyphbits; i++ ) {
	  if( glyphbits > 32 ) {
	  	gerec->GlyphIndex[i] = readBits(f, 32);
	  	glyphbits -= 32;
  	} else {
	 	gerec->GlyphIndex[i] = readBits(f, glyphbits);
	 	glyphbits = 0;
  	}
  }

  nmalloc = ( advancebits < 1 ? 1 : ((advancebits+31)/32) ) * sizeof(UI32);
  gerec->GlyphAdvance = malloc(nmalloc);
  gerec->GlyphAdvance[0] = 0; /* for advancebits == 0 */
  for( i=0; advancebits; i++ ) {
	  if( advancebits > 32 ) {
	  	gerec->GlyphAdvance[i] = readBits(f, 32);
	  	advancebits -= 32;
  	} else {
	 	gerec->GlyphAdvance[i] = readBits(f, advancebits);
	 	advancebits = 0;
  	}
  }
}

int
parseSWF_TEXTRECORD (FILE * f, struct SWF_TEXTRECORD *brec, int glyphbits, int advancebits, int level)
{
  int i;

  byteAlign ();

  brec->TextRecordType = readBits (f, 1);
  brec->StyleFlagsReserved = readBits (f, 3);
  brec->StyleFlagHasFont = readBits (f, 1);
  brec->StyleFlagHasColor = readBits (f, 1);
  brec->StyleFlagHasYOffset = readBits (f, 1);
  brec->StyleFlagHasXOffset = readBits (f, 1);
  if( brec->TextRecordType == 0 )
	  return 0;
  if( brec->StyleFlagHasFont )
    brec->FontID = readUInt16 (f);
  if( brec->StyleFlagHasColor ) {
    if( level > 1 )
	    parseSWF_RGBA(f, &brec->TextColor );
    else
	    parseSWF_RGB(f, &brec->TextColor );
  }
  if( brec->StyleFlagHasXOffset )
    brec->XOffset = readSInt16 (f);
  if( brec->StyleFlagHasYOffset )
    brec->YOffset = readSInt16 (f);
  if( brec->StyleFlagHasFont )
    brec->TextHeight = readUInt16 (f);
  brec->GlyphCount = readUInt8 (f);
  brec->GlyphEntries = malloc(brec->GlyphCount * sizeof(SWF_GLYPHENTRY) );
  byteAlign ();
  for(i=0;i<brec->GlyphCount;i++)
	  parseSWF_GLYPHENTRY(f, &(brec->GlyphEntries[i]), glyphbits, advancebits );

  return 1;
}

int
parseSWF_CLIPEVENTFLAGS (FILE * f, struct SWF_CLIPEVENTFLAGS *cflags)
{
  byteAlign ();

  cflags->ClipEventKeyUp = readBits (f, 1);
  cflags->ClipEventKeyDown = readBits (f, 1);
  cflags->ClipEventMouseUp = readBits (f, 1);
  cflags->ClipEventMouseDown = readBits (f, 1);
  cflags->ClipEventMouseMove = readBits (f, 1);
  cflags->ClipEventUnload = readBits (f, 1);
  cflags->ClipEventEnterFrame = readBits (f, 1);
  cflags->ClipEventLoad = readBits (f, 1);
  cflags->ClipEventDragOver = readBits (f, 1);
  cflags->ClipEventRollOut = readBits (f, 1);
  cflags->ClipEventRollOver = readBits (f, 1);
  cflags->ClipEventReleaseOutside = readBits (f, 1);
  cflags->ClipEventRelease = readBits (f, 1);
  cflags->ClipEventPress = readBits (f, 1);
  cflags->ClipEventInitialize = readBits (f, 1);
  cflags->ClipEventData = readBits (f, 1);
  if( m.version >= 6 ) {
    cflags->Reserved = readBits (f, 5);
    cflags->ClipEventConstruct = readBits (f, 1);
    cflags->ClipEventKeyPress = readBits (f, 1);
    cflags->ClipEventDragOut = readBits (f, 1);
    cflags->Reserved2 = readBits (f, 8);
  } else {
    cflags->Reserved = 0;
    cflags->ClipEventConstruct = 0;
    cflags->ClipEventKeyPress = 0;
    cflags->ClipEventDragOut = 0;
    cflags->Reserved2 = 0;
  }
 

  return cflags->ClipEventKeyUp|cflags->ClipEventKeyDown|cflags->ClipEventMouseUp|cflags->ClipEventMouseDown|cflags->ClipEventMouseMove|cflags->ClipEventUnload|cflags->ClipEventEnterFrame|cflags->ClipEventLoad|cflags->ClipEventDragOver|cflags->ClipEventRollOut|cflags->ClipEventRollOver|cflags->ClipEventReleaseOutside|cflags->ClipEventRelease|cflags->ClipEventPress|cflags->ClipEventInitialize|cflags->ClipEventData|cflags->ClipEventConstruct|cflags->ClipEventKeyPress|cflags->ClipEventDragOut;
}

int
parseSWF_CLIPACTIONRECORD (FILE * f, struct SWF_CLIPACTIONRECORD *carec)
{
  int length,end;
  byteAlign ();

  if( parseSWF_CLIPEVENTFLAGS( f, &(carec->EventFlag) ) == 0 )
	  return 0;
  carec->ActionRecordSize = readUInt32 (f);
  if( carec->EventFlag.ClipEventKeyPress ) {
  	carec->KeyCode = readUInt8 (f);
	length = carec->ActionRecordSize-1;
  } else {
	length = carec->ActionRecordSize;
  }
  end = fileOffset + length;
  /* carec->Actions = decompile5Action (f, length, 1); */
  carec->Actions =
    (SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
  carec->numActions = 0;

  while ( fileOffset < end ) {
      parseSWF_ACTIONRECORD (f, &(carec->numActions), carec->Actions);
      carec->Actions = (SWF_ACTION *) realloc (carec->Actions,
							 (++carec->
							  numActions +
							  1) *
							 sizeof
							 (SWF_ACTION));
    }

  return 1;
}

void
parseSWF_CLIPACTIONS (FILE * f, struct SWF_CLIPACTIONS *clipact, int end)
{
  byteAlign ();
  clipact->Reserved = readUInt16 (f);
  parseSWF_CLIPEVENTFLAGS( f, &(clipact->AllEventFlags) );
  
  clipact->ClipActionRecords =
    (SWF_CLIPACTIONRECORD *) calloc (1, sizeof (SWF_CLIPACTIONRECORD));
  clipact->NumClipRecords = 0;
  while (parseSWF_CLIPACTIONRECORD
	 (f, &(clipact->ClipActionRecords[clipact->NumClipRecords++]) ) )
  {
    if(fileOffset >= end)
      return;
    clipact->ClipActionRecords = (SWF_CLIPACTIONRECORD *) realloc (clipact->ClipActionRecords,
							 (clipact->
							  NumClipRecords +
							  1) *
							 sizeof
							 (SWF_CLIPACTIONRECORD));
  }
  clipact->ClipActionEndFlag = readUInt16(f);
}

void
parseSWF_GRADIENTRECORD (FILE * f, struct SWF_GRADIENTRECORD *gradientrec, int level)
{
  gradientrec->Ratio = readUInt8 (f);
  if (level < 3)
     parseSWF_RGB (f, &gradientrec->Color);
  else
     parseSWF_RGBA (f, &gradientrec->Color);
}

void
parseSWF_FOCALGRADIENT (FILE * f, struct SWF_FOCALGRADIENT *gradient, int level)
{
  int i;
  gradient->SpreadMode = readBits(f, 2);
  gradient->InterpolationMode = readBits(f, 2);
  gradient->NumGradients = readBits (f, 4);
  if(gradient->NumGradients > 15) {
	  fprintf(stderr, "%d gradients in SWF_FOCALGRADIENT, expected a max of 15\n", gradient->NumGradients );
	  /*exit(1);*/
  }

  for (i = 0; i < gradient->NumGradients; i++)
    parseSWF_GRADIENTRECORD (f, &(gradient->GradientRecords[i]), level);
  
  gradient->FocalPoint = readUInt16(f); 
}

void
parseSWF_GRADIENT (FILE * f, struct SWF_GRADIENT *gradient, int level)
{
  int i;
  gradient->SpreadMode = readBits(f, 2);
  gradient->InterpolationMode = readBits(f, 2);
  gradient->NumGradients = readBits (f, 4);
  if((gradient->NumGradients > 8  && level < 4) || (gradient->NumGradients > 15  && level == 4)) {
	  fprintf(stderr, "%d gradients in SWF_GRADiENT, expected a max of %d\n", gradient->NumGradients, level<4 ? 8 : 15 );
	  /*exit(1);*/
  }

  for (i = 0; i < gradient->NumGradients; i++)
    parseSWF_GRADIENTRECORD (f, &(gradient->GradientRecords[i]), level);
}

int
parseSWF_SHAPERECORD (FILE * f, SWF_SHAPERECORD * shape, int *fillBits,
		      int *lineBits, int level)
{
  UI16 tmpbits;
  memset (shape, 0, sizeof (SWF_SHAPERECORD));
  shape->EndShape.TypeFlag = readBits (f, 1);
  if (shape->EndShape.TypeFlag)
    {
      /* An Edge Record */
      shape->StraightEdge.StraightEdge = readBits (f, 1);
      if (shape->StraightEdge.StraightEdge == 1)
	{
	  /* A Straight Edge Record */
	  shape->StraightEdge.NumBits = readBits (f, 4);
	  shape->StraightEdge.GeneralLineFlag = readBits (f, 1);
	  if (shape->StraightEdge.GeneralLineFlag)
	    {
	      shape->StraightEdge.DeltaX =
		readSBits (f, shape->StraightEdge.NumBits + 2);
	      shape->StraightEdge.DeltaY =
		readSBits (f, shape->StraightEdge.NumBits + 2);
	    }
	  else
	    {
	      shape->StraightEdge.VertLineFlag = readBits (f, 1);
	      if (shape->StraightEdge.VertLineFlag)
		{
		  shape->StraightEdge.VLDeltaY =
		    readSBits (f, shape->StraightEdge.NumBits + 2);
		}
	      else
		{
		  shape->StraightEdge.VLDeltaX =
		    readSBits (f, shape->StraightEdge.NumBits + 2);
		}
	    }
	}
      else
	{ 
	  /* A Curved Edge Record */
	  shape->CurvedEdge.NumBits = readBits (f, 4);
	  shape->CurvedEdge.ControlDeltaX =
	    readSBits (f, shape->CurvedEdge.NumBits + 2);
	  shape->CurvedEdge.ControlDeltaY =
	    readSBits (f, shape->CurvedEdge.NumBits + 2);
	  shape->CurvedEdge.AnchorDeltaX =
	    readSBits (f, shape->CurvedEdge.NumBits + 2);
	  shape->CurvedEdge.AnchorDeltaY =
	    readSBits (f, shape->CurvedEdge.NumBits + 2);
	}
    }
  else
    {
      /* A Non-Edge Record */
      tmpbits = readBits (f, 5);
      if (tmpbits == 0)
	{
	  /* EndShapeRecord */
	  shape->EndShape.EndOfShape = 0;
	  return 0;
	}
      /* StyleChangeRecord - ie one or more of the next 5 bits are set */

      if (tmpbits & (1 << 4))
	shape->StyleChange.StateNewStyles = 1;
      if (tmpbits & (1 << 3))
	shape->StyleChange.StateLineStyle = 1;
      if (tmpbits & (1 << 2))
	shape->StyleChange.StateFillStyle1 = 1;
      if (tmpbits & (1 << 1))
	shape->StyleChange.StateFillStyle0 = 1;
      if (tmpbits & (1 << 0))
	shape->StyleChange.StateMoveTo = 1;

      if (shape->StyleChange.StateMoveTo)
	{
	  shape->StyleChange.MoveBits = readBits (f, 5);
	  shape->StyleChange.MoveDeltaX =
	    readSBits (f, shape->StyleChange.MoveBits);
	  shape->StyleChange.MoveDeltaY =
	    readSBits (f, shape->StyleChange.MoveBits);
	}
      if (shape->StyleChange.StateFillStyle0)
	{
	  shape->StyleChange.FillStyle0 = readBits (f, *fillBits);
	}
      if (shape->StyleChange.StateFillStyle1)
	{
	  shape->StyleChange.FillStyle1 = readBits (f, *fillBits);
	}
      if (shape->StyleChange.StateLineStyle)
	{
	  shape->StyleChange.LineStyle = readBits (f, *lineBits);
	}
      if (shape->StyleChange.StateNewStyles)
	{
	  parseSWF_FILLSTYLEARRAY (f, &(shape->StyleChange.FillStyles),
				   level);
	  parseSWF_LINESTYLEARRAY (f, &(shape->StyleChange.LineStyles),
				   level);
	  shape->StyleChange.NumFillBits = *fillBits = readBits (f, 4);
	  shape->StyleChange.NumLineBits = *lineBits = readBits (f, 4);
	}

    }
  return 1;
}

void
parseSWF_FILLSTYLE (FILE * f, SWF_FILLSTYLE * fillstyle, int level)
{
  fillstyle->FillStyleType = readUInt8 (f);
  switch (fillstyle->FillStyleType)
    {
    case 0x00:			/* Solid Fill */
      if (level < 3)
	parseSWF_RGB (f, &fillstyle->Color);
      else
	parseSWF_RGBA (f, &fillstyle->Color);
      break;
    case 0x10:			/* Linear Gradient Fill */
    case 0x12:			/* Radial Gradient Fill */
      parseSWF_MATRIX (f, &fillstyle->GradientMatrix);
      parseSWF_GRADIENT (f, &fillstyle->Gradient, level);
      break;
    case 0x13:
      parseSWF_MATRIX (f, &fillstyle->GradientMatrix);
      parseSWF_FOCALGRADIENT(f, &fillstyle->FocalGradient, level);
      break;
    case 0x40:			/* Repeating Bitmap Fill */
    case 0x41:			/* Clipped Bitmap Fill */
    case 0x42:			/* Non-smoothed Repeating Bitmap Fill */
    case 0x43:			/* Non-smoothed Clipped Bitmap Fill */
      fillstyle->BitmapId = readUInt16 (f);
      parseSWF_MATRIX (f, &fillstyle->BitmapMatrix);
      break;
    }
}

void
parseSWF_FILLSTYLEARRAY (FILE * f, SWF_FILLSTYLEARRAY * fillstyle, int level)
{
  int count, i;
  fillstyle->FillStyleCount = readUInt8 (f);
  count = fillstyle->FillStyleCount;
  if (fillstyle->FillStyleCount == 0xff)
    {
      fillstyle->FillStyleCountExtended = readUInt16 (f);
      count = fillstyle->FillStyleCountExtended;
    }
  fillstyle->FillStyles =
    (SWF_FILLSTYLE *) calloc (count, sizeof (SWF_FILLSTYLE));
  for (i = 0; i < count; i++)
    {
      parseSWF_FILLSTYLE (f, &(fillstyle->FillStyles[i]), level);
    }
}

void
parseSWF_LINESTYLE (FILE * f, SWF_LINESTYLE * linestyle, int level)
{
  linestyle->Width = readUInt16 (f);
  if (level < 3)
    parseSWF_RGB (f, &linestyle->Color);
  else
    parseSWF_RGBA (f, &linestyle->Color);
}

void 
parseSWF_LINESTYLE2 (FILE *f, SWF_LINESTYLE2 *linestyle2, int level)
{
  linestyle2->Width = readUInt16(f);
  linestyle2->StartCapStyle = readBits(f, 2);
  linestyle2->JoinStyle = readBits(f, 2);
  linestyle2->HasFillFlag = readBits(f, 1);
  linestyle2->NoHScaleFlag = readBits(f, 1);
  linestyle2->NoVScaleFlag = readBits(f, 1);
  linestyle2->PixelHintingFlag = readBits(f, 1);
  linestyle2->Reserved = readBits(f, 5);
  linestyle2->NoClose = readBits(f, 1);
  linestyle2->EndCapStyle = readBits(f, 2);
  if(linestyle2->JoinStyle == 2)
	linestyle2->MiterLimitFactor = readUInt16(f);
  if(linestyle2->HasFillFlag == 0)
	parseSWF_RGBA (f, &linestyle2->Color);
  else
	parseSWF_FILLSTYLE(f, &linestyle2->FillType, level);
}

void
parseSWF_LINESTYLEARRAY (FILE * f, SWF_LINESTYLEARRAY * linestyle, int level)
{
  int count, i;

  count = readUInt8 (f);
  if (count == 0xff)
    {
      count = readUInt16(f);
    }
  linestyle->LineStyleCount = count;

  if(level == 4)
  {
    linestyle->LineStyles = NULL;
    linestyle->LineStyles2 = 
      (SWF_LINESTYLE2 *) malloc (count * sizeof (SWF_LINESTYLE2));
  }
  else 
  {
    linestyle->LineStyles =
      (SWF_LINESTYLE *) malloc (count * sizeof (SWF_LINESTYLE));
    linestyle->LineStyles2 = NULL;
  }
  
  for (i = 0; i < count; i++)
  {
    if(level == 4)
      parseSWF_LINESTYLE2 (f, &(linestyle->LineStyles2[i]), level);
    else
      parseSWF_LINESTYLE (f, &(linestyle->LineStyles[i]), level);
  }
}

void
parseSWF_MORPHLINESTYLE (FILE * f, SWF_MORPHLINESTYLE * linestyle)
{
  linestyle->StartWidth = readUInt16 (f);
  linestyle->EndWidth = readUInt16 (f);
  parseSWF_RGBA (f, &linestyle->StartColor);
  parseSWF_RGBA (f, &linestyle->EndColor);
}

void
parseSWF_MORPHFILLSTYLE (FILE * f, SWF_MORPHFILLSTYLE * fillstyle );
void
parseSWF_MORPHLINESTYLE2 (FILE * f, SWF_MORPHLINESTYLE2 * linestyle2)
{
  linestyle2->StartWidth = readUInt16 (f);
  linestyle2->EndWidth = readUInt16 (f);
  linestyle2->StartCapStyle = readBits(f, 2);
  linestyle2->JoinStyle = readBits(f, 2);
  linestyle2->HasFillFlag = readBits(f, 1);
  linestyle2->NoHScaleFlag = readBits(f, 1);
  linestyle2->NoVScaleFlag = readBits(f, 1);
  linestyle2->PixelHintingFlag = readBits(f, 1);
  linestyle2->Reserved = readBits(f, 5);
  linestyle2->NoClose = readBits(f, 1);
  linestyle2->EndCapStyle = readBits(f, 2);
  if(linestyle2->JoinStyle == 2)
	linestyle2->MiterLimitFactor = readUInt16(f);
  if(linestyle2->HasFillFlag == 0) {
  	parseSWF_RGBA (f, &linestyle2->StartColor);
	parseSWF_RGBA (f, &linestyle2->EndColor);
  }
  else
	parseSWF_MORPHFILLSTYLE(f, &linestyle2->FillType);
}


void
parseSWF_MORPHLINESTYLES (FILE * f, SWF_MORPHLINESTYLES * linestyle, 
                          int version)
{
  int count, i;

  linestyle->LineStyleCount = readUInt8 (f);
  count = linestyle->LineStyleCount;
  if (linestyle->LineStyleCount == 0xff)
    {
      linestyle->LineStyleCountExtended = readUInt16 (f);
      count = linestyle->LineStyleCountExtended;
    }
  if(version == 1)
    linestyle->LineStyles =
      (SWF_MORPHLINESTYLE *) malloc (count * sizeof (SWF_MORPHLINESTYLE));
  else if(version == 2)
    linestyle->LineStyles2 = 
      (SWF_MORPHLINESTYLE2 *) malloc (count * sizeof (SWF_MORPHLINESTYLE2));

  for (i = 0; i < count; i++)
    {
      if(version == 1)
        parseSWF_MORPHLINESTYLE (f, &(linestyle->LineStyles[i]));
      else if(version == 2)
        parseSWF_MORPHLINESTYLE2 (f, &(linestyle->LineStyles2[i]));
      else
        SWF_error("parseSWF_MORPHLINESTYLES: unknow MORPH version\n"); 
    }
}

void
parseSWF_MORPHGRADIENTRECORD (FILE * f, struct SWF_MORPHGRADIENTRECORD *gradientrec)
{
  gradientrec->StartRatio = readUInt8 (f);
  parseSWF_RGBA (f, &gradientrec->StartColor);
  gradientrec->EndRatio = readUInt8 (f);
  parseSWF_RGBA (f, &gradientrec->EndColor);
}

void
parseSWF_MORPHGRADIENT (FILE * f, struct SWF_MORPHGRADIENT *gradient)
{
  int i;
  gradient->NumGradients = readUInt8 (f);
  if( gradient->NumGradients > 8 ) {
	  fprintf(stderr, "%d gradients in SWF_MORPHGRADiENT, expected a max of 8", gradient->NumGradients);
	  /*exit(1);*/
  }
  for (i = 0; i < gradient->NumGradients; i++)
    parseSWF_MORPHGRADIENTRECORD (f, &(gradient->GradientRecords[i]));
}
void
parseSWF_MORPHFILLSTYLE (FILE * f, SWF_MORPHFILLSTYLE * fillstyle )
{
  fillstyle->FillStyleType = readUInt8 (f);
  switch (fillstyle->FillStyleType)
    {
    case 0x00:			/* Solid Fill */
	parseSWF_RGBA (f, &fillstyle->StartColor);
	parseSWF_RGBA (f, &fillstyle->EndColor);
      break;
    case 0x10:			/* Linear Gradient Fill */
    case 0x12:			/* Radial Gradient Fill */
      parseSWF_MATRIX (f, &fillstyle->StartGradientMatrix);
      parseSWF_MATRIX (f, &fillstyle->EndGradientMatrix);
      parseSWF_MORPHGRADIENT (f, &fillstyle->Gradient);
      break;
    case 0x40:			/* Repeating Bitmap Fill */
    case 0x41:			/* Clipped Bitmap Fill */
    case 0x42:			/* Non-smoothed Repeating Bitmap Fill */
    case 0x43:			/* Non-smoothed Clipped Bitmap Fill */
      fillstyle->BitmapId = readUInt16 (f);
      parseSWF_MATRIX (f, &fillstyle->StartBitmapMatrix);
      parseSWF_MATRIX (f, &fillstyle->EndBitmapMatrix);
      break;
    }
}
void
parseSWF_MORPHFILLSTYLES (FILE * f, SWF_MORPHFILLSTYLES * fillstyle )
{
  int count, i;
  fillstyle->FillStyleCount = readUInt8 (f);
  count = fillstyle->FillStyleCount;
  if (fillstyle->FillStyleCount == 0xff)
    {
      fillstyle->FillStyleCountExtended = readUInt16 (f);
      count = fillstyle->FillStyleCountExtended;
    }
  fillstyle->FillStyles =
    (SWF_MORPHFILLSTYLE *) calloc (count, sizeof (SWF_MORPHFILLSTYLE));
  for (i = 0; i < count; i++)
    {
      parseSWF_MORPHFILLSTYLE (f, &(fillstyle->FillStyles[i]));
    }
}

void
parseSWF_SHAPE (FILE * f, SWF_SHAPE * shape, int level, int len)
{
  int fillBits, lineBits;
  int end;	
  byteAlign ();

  end = fileOffset + len;
  shape->NumFillBits = fillBits = readBits (f, 4);
  shape->NumLineBits = lineBits = readBits (f, 4);
  shape->ShapeRecords =
    (SWF_SHAPERECORD *) calloc (1, sizeof (SWF_SHAPERECORD));
  shape->NumShapeRecords = 0;
  while (fileOffset < end) 
  {
    size_t size;
    SWF_SHAPERECORD *rec = &(shape->ShapeRecords[shape->NumShapeRecords]);
    int ret = parseSWF_SHAPERECORD(f, rec, &fillBits, &lineBits, level);
    if(!ret)
	return;

    shape->NumShapeRecords++;
    size = (shape->NumShapeRecords + 1) * sizeof(SWF_SHAPERECORD);
    shape->ShapeRecords = (SWF_SHAPERECORD *)realloc (shape->ShapeRecords, size);
  }
}

void
parseSWF_SHAPEWITHSTYLE (FILE * f, SWF_SHAPEWITHSTYLE * shape, int level)
{
  int fillBits, lineBits;
  memset (shape, 0, sizeof (SWF_SHAPEWITHSTYLE));

  parseSWF_FILLSTYLEARRAY (f, &shape->FillStyles, level);
  parseSWF_LINESTYLEARRAY (f, &shape->LineStyles, level);

  byteAlign ();

  shape->NumFillBits = fillBits = readBits (f, 4);
  shape->NumLineBits = lineBits = readBits (f, 4);

  shape->ShapeRecords =
    (SWF_SHAPERECORD *) calloc (1, sizeof (SWF_SHAPERECORD));
  shape->NumShapeRecords = 0;
  while (parseSWF_SHAPERECORD
	 (f, &(shape->ShapeRecords[shape->NumShapeRecords++]), &fillBits,
	  &lineBits, level))
    {
      shape->ShapeRecords = (SWF_SHAPERECORD *) realloc (shape->ShapeRecords,
							 (shape->
							  NumShapeRecords +
							  1) *
							 sizeof
							 (SWF_SHAPERECORD));
    }
}

/* Parse Action types */

#define ACT_BEGIN(acttype) \
	struct acttype *act;\
	act=(struct acttype *)action; \
	act->Length = readUInt16(f);

#define ACT_BEGIN_NOLEN(acttype) \
	struct acttype *act;\
	act=(struct acttype *)action;

int
parseSWF_ACTIONRECORD(FILE * f, int *thisactionp, SWF_ACTION *actions)
{
	int thisaction = *thisactionp;
	SWF_ACTION *action = &(actions[thisaction]);

	//fprintf(stderr,"ACTION[%d] Offset %d\n", thisaction, fileOffset );

	action->SWF_ACTIONRECORD.Offset = fileOffset; /* remember where it came from */
	if( (action->SWF_ACTIONRECORD.ActionCode = readUInt8(f)) == SWFACTION_END )
		return 0;
	/*
	 * Actions without the high bit set take no additional
	 * arguments, so we are done for these types.
	 */
	if( !(action->SWF_ACTIONRECORD.ActionCode&0x80) ) {
		action->SWF_ACTIONRECORD.Length = 1; /* Fill in the size for later use */
		return 1;
	}

	action->SWF_ACTIONRECORD.Length = 0; /* make valgrind happy */
	/*
	 * Actions with the high bit set take additional
	 * arguments, so we have to parse each one uniquely.
	 */
	switch( action->SWF_ACTIONRECORD.ActionCode ) {
		/* v3 actions */
	case SWFACTION_GOTOFRAME:
		{
		ACT_BEGIN(SWF_ACTIONGOTOFRAME)
		act->Frame = readUInt16(f);
		break;
		}
	case SWFACTION_GETURL:
		{
		ACT_BEGIN(SWF_ACTIONGETURL)
		act->UrlString = readString(f);
		act->TargetString = readString(f);
		break;
		}
	case SWFACTION_WAITFORFRAME:
		{
		ACT_BEGIN(SWF_ACTIONWAITFORFRAME)
		act->Frame = readUInt16(f);
		act->SkipCount = readUInt8(f);
		break;
		}
	case SWFACTION_SETTARGET:
		{
		ACT_BEGIN(SWF_ACTIONSETTARGET)
		act->TargetName = readString(f);
		break;
		}
	case SWFACTION_GOTOLABEL:
		{
		ACT_BEGIN(SWF_ACTIONGOTOLABEL)
		act->FrameLabel = readString(f);
		break;
		}


		/* v4 actions */
	case SWFACTION_PUSH:
		{
		int end;
		struct SWF_ACTIONPUSHPARAM *param;
		ACT_BEGIN(SWF_ACTIONPUSH)

		end = fileOffset + act->Length;
  		act->Params = (struct SWF_ACTIONPUSHPARAM *) calloc (1, sizeof (struct SWF_ACTIONPUSHPARAM));
  		act->NumParam = 0;
  		while ( fileOffset < end ) {
			param = &(act->Params[act->NumParam++]);
			param->Type = readUInt8(f);
			switch( param->Type ) {
			case 0: /* STRING */
				param->p.String = readString(f);
				break;
			case 1: /* FLOAT */
				param->p.Float = readFloat(f);
				break;
			case 2: /* NULL */
			case 3: /* Undefined */
				break;
			case 4: /* Register */
				param->p.RegisterNumber = readUInt8(f);
				break;
			case 5: /* BOOLEAN */
				param->p.Boolean = readUInt8(f);
				break;
			case 6: /* DOUBLE */
				param->p.Double = readDouble(f);
				break;
			case 7: /* INTEGER */
				param->p.Integer = readSInt32(f);
				break;
			case 8: /* CONSTANT8 */
				param->p.Constant8 = readUInt8(f);
				break;
			case 9: /* CONSTANT16 */
				param->p.Constant16 = readUInt16(f);
				break;
			default:
				printf("Unknown data type to push %x\n", param->Type );
				exit(1);
			}
      			act->Params = (struct SWF_ACTIONPUSHPARAM *) realloc (act->Params,
							 (act->NumParam + 1) *
							 sizeof (struct SWF_ACTIONPUSHPARAM));
    		}
		break;
		}
	case SWFACTION_LOGICALNOT:
		{
		ACT_BEGIN_NOLEN(SWF_ACTIONNOT)
		act->Boolean = readUInt32(f);
		fprintf(stderr,"NOT param: %d\n", act->Boolean );
		break;
		}
	case SWFACTION_CALLFRAME:
		{
		ACT_BEGIN(SWF_ACTIONCALL)
		// readUInt16(f);		/* seems to be an exception: NO reading here */
		break;
		}
	case SWFACTION_JUMP:
		{
		ACT_BEGIN(SWF_ACTIONJUMP)
		act->BranchOffset = readUInt16(f);
		break;
		}
	case SWFACTION_IF:
		{
		int i,j,k, curroffset;
		ACT_BEGIN(SWF_ACTIONIF)

		act->BranchOffset = readUInt16(f);
		/*
		 * Set curroffset to point to the next action so that an
		 * offset of zero matches it.
		 */
		curroffset=(action->SWF_ACTIONRECORD.Offset-actions[0].SWF_ACTIONRECORD.Offset)+
			    action->SWF_ACTIONRECORD.Length+3; /* Action + Length bytes not included in the length */
		if( act->BranchOffset < 0 ) {
			/*
			 * We are branching to records that we already have in the array. Just
			 * allocate new space for the if clause, and copy the records there, and then
			 * fix the count of records in actions[], and put this record at the new
			 * end of actions[].
			 */
		    for(i=0;i<=thisaction;i++) {
			if( (actions[i].SWF_ACTIONRECORD.Offset-actions[0].SWF_ACTIONRECORD.Offset) == curroffset+act->BranchOffset ) break;
		    }
		    if( i>=thisaction ) {
                            SWF_warn("Failed to find branch target!!!\n");
                            SWF_warn("Looking for: %d\n\n", curroffset + act->BranchOffset);
                            act->BranchOffset=0;	/* despite the problem ..*/
                            i=thisaction;		/* ..continue with empty block */
		    }
		    act->numActions = thisaction-i;
		    act->Actions = (union SWF_ACTION *) calloc (act->numActions, sizeof (SWF_ACTION));
		    for(j=i,k=0;j<thisaction;j++,k++)
			    act->Actions[k] = actions[j];
		    actions[i]=*((SWF_ACTION *)act);	/* added by ak,2006 */
		    *thisactionp = i;
		} else {
			/*
			 * We are branching to records not yet parsed. Just handle this in the
			 * same manner used for with, try, etc.
			 */
		    act->Actions = (union SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
		    act->numActions = 0;
		    while ( (fileOffset-actions[0].SWF_ACTIONRECORD.Offset) < curroffset+act->BranchOffset ) {
			parseSWF_ACTIONRECORD (f, &(act->numActions), (SWF_ACTION *)act->Actions);
			act->Actions = (union SWF_ACTION *) realloc (act->Actions,
							 (++act->numActions + 1) *
							 sizeof (SWF_ACTION));
		    }
		}
		break;
		}
	case SWFACTION_GETURL2:
		{
		ACT_BEGIN(SWF_ACTIONGETURL2)
		// act->f.Flags = readUInt8(f);
		act->f.FlagBits.LoadTargetFlag = readBits(f,1);
		act->f.FlagBits.LoadVariableFlag = readBits(f,1);
		act->f.FlagBits.Reserved = readBits(f,4);
		act->f.FlagBits.SendVarsMethod = readBits(f,2);
		break;
		}
	case SWFACTION_GOTOFRAME2:
		{
		ACT_BEGIN(SWF_ACTIONGOTOFRAME2)
		act->f.FlagBits.Reserved = readBits(f,6);
		act->f.FlagBits.SceneBiasFlag = readBits(f,1);
		act->f.FlagBits.PlayFlag = readBits(f,1);
		if( act->f.FlagBits.SceneBiasFlag ) {
			act->SceneBias = readUInt16(f);
		}
		break;
		}
	case SWFACTION_WAITFORFRAME2:
		{
		ACT_BEGIN(SWF_ACTIONWAITFORFRAME2)
		act->SkipCount = readUInt8(f);
		break;
		}


		/* v5 actions */
	case SWFACTION_CONSTANTPOOL:
		{
		int i;
		ACT_BEGIN(SWF_ACTIONCONSTANTPOOL)

		act->Count = readUInt16(f);
		act->ConstantPool = malloc(act->Count*sizeof(char *));
		for(i=0;i<act->Count;i++) {
			act->ConstantPool[i] = readString(f);
		}
		break;
		}
	case SWFACTION_DEFINEFUNCTION:
		{
		int i, end2;
		ACT_BEGIN(SWF_ACTIONDEFINEFUNCTION)

		act->FunctionName = readString(f);
		act->NumParams = readSInt16(f);
		act->Params = (STRING *)malloc(act->NumParams*sizeof(char *));
		for(i=0;i<act->NumParams;i++) {
			act->Params[i] = readString(f);
			/* printf("Read %s\n", act->ConstantPool[i] ); */
		}
		act->CodeSize = readSInt16(f);
		end2 = fileOffset + act->CodeSize;
		act->Actions = (union SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
		act->numActions = 0;
		while ( fileOffset < end2 ) {
			parseSWF_ACTIONRECORD (f, &(act->numActions), (SWF_ACTION *)act->Actions);
			act->Actions = (union SWF_ACTION *) realloc (act->Actions,
							 (++act->numActions + 1) *
							 sizeof (SWF_ACTION));
		    }
		break;
		}
	case SWFACTION_WITH:
		{
		int end;
		ACT_BEGIN(SWF_ACTIONWITH)

		act->Size = readUInt16(f);
		end = fileOffset + act->Size;
		act->Actions = (union SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
		act->numActions = 0;
		while ( fileOffset < end ) {
			parseSWF_ACTIONRECORD (f, &(act->numActions), (SWF_ACTION *)act->Actions);
			act->Actions = (union SWF_ACTION *) realloc (act->Actions,
							 (++act->numActions + 1) *
							 sizeof (SWF_ACTION));
		    }
		break;
		}
	case SWFACTION_STOREREGISTER:
		{
		ACT_BEGIN(SWF_ACTIONSTOREREGISTER)

		act->Register = readUInt8(f);
		break;
		}


		/* v6 actions */

		/* v7 actions */
	case SWFACTION_DEFINEFUNCTION2:
		{
		int i, end2;
		ACT_BEGIN(SWF_ACTIONDEFINEFUNCTION2)

		act->FunctionName = readString(f);
		act->NumParams = readSInt16(f);
		act->RegisterCount = readSInt8(f);
		act->PreloadParentFlag = readBits(f,1);
		act->PreloadRootFlag = readBits(f,1);
		act->SuppressSuperFlag = readBits(f,1);
		act->PreloadSuperFlag = readBits(f,1);
		act->SuppressArgumentsFlag = readBits(f,1);
		act->PreloadArgumentsFlag = readBits(f,1);
		act->SuppressThisFlag = readBits(f,1);
		act->PreloadThisFlag = readBits(f,1);
		act->Reserved = readBits(f,7);
		act->PreloadGlobalFlag = readBits(f,1);
		act->Params = (struct REGISTERPARAM *)malloc(act->NumParams*sizeof(struct REGISTERPARAM));
		for(i=0;i<act->NumParams;i++) {
			act->Params[i].Register = readUInt8(f);
			act->Params[i].ParamName = readString(f);
		}
		act->CodeSize = readSInt16(f);
		end2 = fileOffset + act->CodeSize;
		act->Actions = (union SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
		act->numActions = 0;
		while ( fileOffset < end2 ) {
			parseSWF_ACTIONRECORD (f, &(act->numActions), (SWF_ACTION *)act->Actions);
			act->Actions = (union SWF_ACTION *) realloc (act->Actions,
							 (++act->numActions + 1) *
							 sizeof (SWF_ACTION));
		    }
		break;
		}
	case SWFACTION_TRY:
		{
		int end2;
		ACT_BEGIN(SWF_ACTIONTRY)

		act->Reserved = readBits(f,5);
		act->CatchInRegisterFlag = readBits(f,1);
		act->FinallyBlockFlag = readBits(f,1);
		act->CatchBlockFlag = readBits(f,1);
		act->TrySize = readSInt16(f);
		act->CatchSize = readSInt16(f);
		act->FinallySize = readSInt16(f);
		if( act->CatchInRegisterFlag == 0 ) {
			act->CatchName = readString(f);
		} else {
			act->CatchRegister = readUInt8(f);
		}

		/* Try Body */
		end2 = fileOffset + act->TrySize;
		act->TryActs = (union SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
		act->numTryActs = 0;
		while ( fileOffset < end2 ) {
			parseSWF_ACTIONRECORD (f, &(act->numTryActs), (SWF_ACTION *)act->TryActs);
			act->TryActs = (union SWF_ACTION *) realloc (act->TryActs,
							 (++act->numTryActs + 1) *
							 sizeof (SWF_ACTION));
		    }

		/* Catch Body */
		end2 = fileOffset + act->CatchSize;
		act->CatchActs = (union SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
		act->numCatchActs = 0;
		while ( fileOffset < end2 ) {
			parseSWF_ACTIONRECORD (f, &(act->numCatchActs), (SWF_ACTION *)act->CatchActs);
			act->CatchActs = (union SWF_ACTION *) realloc (act->CatchActs,
							 (++act->numCatchActs + 1) *
							 sizeof (SWF_ACTION));
		    }

		/* Finally Body */
		end2 = fileOffset + act->FinallySize;
		act->FinallyActs = (union SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
		act->numFinallyActs = 0;
		while ( fileOffset < end2 ) {
			parseSWF_ACTIONRECORD (f, &(act->numFinallyActs), (SWF_ACTION *)act->FinallyActs);
			act->FinallyActs = (union SWF_ACTION *) realloc (act->FinallyActs,
							 (++act->numFinallyActs + 1) *
							 sizeof (SWF_ACTION));
		    }
		break;
		}
	default:
		printf("Not parsing action %x length %x\n", action->SWF_ACTIONRECORD.ActionCode, action->SWF_ACTIONRECORD.Length );
		peekBytes(f,100);
		exit(1);
	}
	return 1;
}

void 
parseSWF_DROPSHADOWFILTER(FILE *f, SWF_DROPSHADOWFILTER *filter)
{
	parseSWF_RGBA(f, &filter->DropShadowColor);
	filter->BlurX = readUInt32(f);
	filter->BlurY = readUInt32(f);
	filter->Angle = readUInt32(f);
	filter->Distance = readUInt32(f);
	filter->Strength = readUInt16(f);
	filter->InnerShadow = readBits(f, 1);
	filter->Kockout = readBits(f, 1);
	filter->CompositeSource = readBits(f, 1);
	filter->Passes = readBits(f, 5);
} 

void 
parseSWF_BLURFILTER(FILE *f, SWF_BLURFILTER *filter)
{
	filter->BlurX = readUInt32(f);
	filter->BlurY = readUInt32(f);
	filter->Passes = readBits(f, 5);
	filter->Reserved = readBits(f, 3);
}

void 
parseSWF_GLOWFILTER(FILE *f, SWF_GLOWFILTER *filter)
{
	parseSWF_RGBA(f, &filter->GlowColor);
	filter->BlurX = readUInt32(f);
	filter->BlurY = readUInt32(f);
	filter->Strength = readUInt16(f);
	filter->InnerGlow = readBits(f, 1);
	filter->Kockout = readBits(f, 1);
	filter->CompositeSource = readBits(f, 1);
	filter->Passes = readBits(f, 5);
}

void 
parseSWF_BEVELFILTER(FILE *f, SWF_BEVELFILTER *filter)
{
	parseSWF_RGBA(f, &filter->ShadowColor);
	parseSWF_RGBA(f, &filter->HighlightColor);
	filter->BlurX = readUInt32(f);
	filter->BlurY = readUInt32(f);
	filter->Angle = readUInt32(f);
	filter->Distance = readUInt32(f);
	filter->Strength = readUInt16(f);
	filter->InnerShadow = readBits(f, 1);
	filter->Kockout = readBits(f, 1);
	filter->CompositeSource = readBits(f, 1);
	filter->OnTop = readBits(f, 1);
	filter->Passes = readBits(f, 4);
}

void 
parseSWF_GRADIENTFILTER(FILE *f, SWF_GRADIENTFILTER *filter)
{
	int i, size;

	filter->NumColors = readUInt8(f);
	size = filter->NumColors * sizeof(SWF_RGBA);
	filter->GradientColors = (SWF_RGBA *)malloc(size);
	for(i = 0; i < filter->NumColors; i++)
		parseSWF_RGBA(f, filter->GradientColors + i);

	size = filter->NumColors * sizeof(UI8);
	filter->GradientRatio = (UI8 *)malloc(size);
	for(i = 0; i < filter->NumColors; i++)
		filter->GradientRatio[i] = readUInt8(f);

	filter->BlurX = readUInt32(f);
	filter->BlurY = readUInt32(f);
	filter->Angle = readUInt32(f);
	filter->Distance = readUInt32(f);
	filter->Strength = readUInt16(f);
	filter->InnerShadow = readBits(f, 1);
	filter->Kockout = readBits(f, 1);
	filter->CompositeSource = readBits(f, 1);
	filter->OnTop = readBits(f, 1);
	filter->Passes = readBits(f, 4);
}

void 
parseSWF_CONVOLUTIONFILTER(FILE *f, SWF_CONVOLUTIONFILTER *filter)
{
	int size, i;

	filter->MatrixX = readUInt8(f);
	filter->MatrixY = readUInt8(f);
	filter->Divisor = readUInt32(f);
	filter->Bias = readUInt32(f);

	size = filter->MatrixX * filter->MatrixY * sizeof(UI32);
	filter->Matrix = (FLOAT *)malloc(size);
	for(i = 0; i < filter->MatrixX * filter->MatrixY; i++)
		filter->Matrix[i] = readUInt32(f);

	parseSWF_RGBA(f, &filter->DefaultColor);
	filter->Reserved = readBits(f, 6);
	filter->Clamp = readBits(f, 1);
	filter->PreserveAlpha = readBits(f, 1);	
}

void 
parseSWF_COLORMATRIXFILTER(FILE *f, SWF_COLORMATRIXFILTER *filter)
{
	int i;
	
	for(i = 0; i < 20; i++)
		filter->Matrix[i] = readFloat(f);
}

void 
parseSWF_FILTER(FILE *f, SWF_FILTER *filter)
{
	filter->FilterId = readUInt8(f);

	switch(filter->FilterId)
	{
		case FILTER_DROPSHADOW:
			parseSWF_DROPSHADOWFILTER(f, &filter->filter.dropShadow);
			break;
		case FILTER_BLUR:
			parseSWF_BLURFILTER(f, &filter->filter.blur);
			break;
		case FILTER_GLOW:
			parseSWF_GLOWFILTER(f, &filter->filter.glow);
			break;
		case FILTER_BEVEL:
			parseSWF_BEVELFILTER(f, &filter->filter.bevel);
			break;
		case FILTER_CONVOLUTION:
			parseSWF_CONVOLUTIONFILTER(f, &filter->filter.convolution);
			break;
		case FILTER_COLORMATRIX:
			parseSWF_COLORMATRIXFILTER(f, &filter->filter.colorMatrix);
			break;
		case FILTER_GRADIENTGLOW:
			parseSWF_GRADIENTFILTER(f, &filter->filter.gradientGlow);
			break;
		case FILTER_GRADIENTBEVEL:
			parseSWF_GRADIENTFILTER(f, &filter->filter.gradientBevel);
			break;
		default:
			printf("unknown filter %i\n", filter->FilterId);
	}
}

void 
parseSWF_FILTERLIST(FILE *f, SWF_FILTERLIST *list)
{
	int i, size;
	list->NumberOfFilters = readUInt8(f);
	size = list->NumberOfFilters * sizeof(SWF_FILTER);
	list->Filter = (SWF_FILTER *)malloc(size);

	for(i = 0; i < list->NumberOfFilters; i++)
		parseSWF_FILTER(f, list->Filter + i);
}

/* Parse Block types */

SWF_Parserstruct *
parseSWF_CHARACTERSET (FILE * f, int length)
{
  PAR_BEGIN (SWF_CHARACTERSET);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEBITS (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_DEFINEBITS);

  parserrec->CharacterID = readUInt16 (f);
  parserrec->JPEGDataSize = end-fileOffset;
  parserrec->JPEGData = (UI8 *)readBytes(f,end-fileOffset);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEBITSJPEG2 (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_DEFINEBITSJPEG2);

  parserrec->CharacterID = readUInt16 (f);
  parserrec->JPEGDataSize = end-fileOffset;
  parserrec->JPEGData = (UI8 *)readBytes(f,end-fileOffset);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEBITSJPEG3 (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_DEFINEBITSJPEG3);

  parserrec->CharacterID = readUInt16 (f);
  parserrec->AlphaDataOffset = readUInt32 (f);
  parserrec->JPEGData = (UI8 *)readBytes(f,parserrec->AlphaDataOffset);
  parserrec->AlphaDataSize = end-fileOffset;
  parserrec->BitmapAlphaData = (UI8 *)readBytes(f,end-fileOffset);


  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEBITSPTR (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINEBITSPTR);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEBUTTON (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINEBUTTON);
  parserrec->ButtonId = readUInt16 (f);
  parserrec->numCharacters = 0;
  parserrec->Characters = (SWF_BUTTONRECORD *)calloc(1, sizeof (SWF_BUTTONRECORD));
  while (parseSWF_BUTTONRECORD (f, &(parserrec->Characters[parserrec->numCharacters++]), 1 ))
  {
    int size = (parserrec->numCharacters + 1) * sizeof(SWF_BUTTONRECORD);
    parserrec->Characters = (SWF_BUTTONRECORD *) realloc (parserrec->Characters, size);
  }
  parserrec->CharacterEndFlag = 0; // handled by parseSWF_BUTTONRECORD

  parserrec->Actions = (SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
  parserrec->numActions = 0;
  while (parseSWF_ACTIONRECORD (f, &(parserrec->numActions), parserrec->Actions))
  {
    int size = (++parserrec->numActions + 1) * sizeof(SWF_ACTION);
    parserrec->Actions = (SWF_ACTION *) realloc (parserrec->Actions, size);
  }
  parserrec->ActionEndFlag = 0; 
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEBUTTON2 (FILE * f, int length)
{
  int stop;
  int end = fileOffset + length;
  PAR_BEGIN (SWF_DEFINEBUTTON2);

  byteAlign();

  parserrec->Buttonid = readUInt16 (f);
  parserrec->ReservedFlags = readBits (f, 7);
  parserrec->TrackAsMenu = readBits (f, 1);
  stop = fileOffset;
  parserrec->ActionOffset = readUInt16 (f);
  if( parserrec->ActionOffset )
    stop += parserrec->ActionOffset;
  else
    stop = end;
  parserrec->numCharacters = 0;
  parserrec->Characters =
    (SWF_BUTTONRECORD *) calloc (1, sizeof (SWF_BUTTONRECORD));

  while ( fileOffset < stop-1 ) {
    parseSWF_BUTTONRECORD (f, &(parserrec->Characters[parserrec->numCharacters++]), 2 );
    parserrec->Characters = (SWF_BUTTONRECORD *) realloc (parserrec->Characters,
							 (parserrec->numCharacters + 1) *
							 sizeof
							 (SWF_BUTTONRECORD));
    }

  parserrec->CharacterEndFlag = readUInt8 (f);
  if ( parserrec->CharacterEndFlag != 0 )
  {
    SWF_warn(" CharacterEndFlag in DefineButton2 != 0");
  }

  parserrec->numActions = 0;
  parserrec->Actions =
    (SWF_BUTTONCONDACTION *) calloc (1, sizeof (SWF_BUTTONCONDACTION));
  while( fileOffset < end && 
       parseSWF_BUTTONCONDACTION (f, &(parserrec->Actions[parserrec->numActions++]), end)) 
  {
    parserrec->Actions = (SWF_BUTTONCONDACTION *) realloc (parserrec->Actions,
							 (parserrec->numActions + 1) *
							 sizeof
							 (SWF_BUTTONCONDACTION));
  }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEBUTTONCXFORM (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINEBUTTONCXFORM);
  parserrec->ButtonId = readUInt16(f);
  parseSWF_CXFORM(f, &parserrec->ButtonColorTransform);
  PAR_END;
}

void parseSWF_SOUNDINFO(FILE *f, struct SWF_SOUNDINFO *si);

SWF_Parserstruct *
parseSWF_DEFINEBUTTONSOUND (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINEBUTTONSOUND);
  parserrec->CharacterID = readUInt16 (f);
  parserrec->ButtonSoundChar0 = readUInt16 (f);
  if (parserrec->ButtonSoundChar0)
    parseSWF_SOUNDINFO(f, &parserrec->ButtonSoundInfo0);
  
  parserrec->ButtonSoundChar1 = readUInt16 (f);
  if (parserrec->ButtonSoundChar1)
    parseSWF_SOUNDINFO(f, &parserrec->ButtonSoundInfo1);
  
  parserrec->ButtonSoundChar2 = readUInt16 (f);
  if (parserrec->ButtonSoundChar2)
    parseSWF_SOUNDINFO(f, &parserrec->ButtonSoundInfo2);

  parserrec->ButtonSoundChar3 = readUInt16 (f);
  if (parserrec->ButtonSoundChar3)
    parseSWF_SOUNDINFO(f, &parserrec->ButtonSoundInfo3);
 
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINECOMMANDOBJ (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINECOMMANDOBJ);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEEDITTEXT (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINEEDITTEXT);

  parserrec->CharacterID = readUInt16 (f);
  parseSWF_RECT (f, &(parserrec->Bounds));
  byteAlign ();
  parserrec->HasText = readBits (f, 1);
  parserrec->WordWrap = readBits (f, 1);
  parserrec->Multiline = readBits (f, 1);
  parserrec->Password = readBits (f, 1);
  parserrec->ReadOnly = readBits (f, 1);
  parserrec->HasTextColor = readBits (f, 1);
  parserrec->HasMaxLength = readBits (f, 1);
  parserrec->HasFont = readBits (f, 1);
  parserrec->HasFontClass = readBits (f, 1);
  parserrec->AutoSize = readBits (f, 1);
  parserrec->HasLayout = readBits (f, 1);
  parserrec->NoSelect = readBits (f, 1);
  parserrec->Border = readBits (f, 1);
  parserrec->WasStatic = readBits (f, 1);
  parserrec->HTML = readBits (f, 1);
  parserrec->UseOutlines = readBits (f, 1);
  if (parserrec->HasFont)
    parserrec->FontID = readUInt16 (f);

  if (parserrec->HasFontClass)
    parserrec->FontClass = readString(f);
  
  if (parserrec->HasFont)
    parserrec->FontHeight = readUInt16 (f);
    
  if (parserrec->HasTextColor)
    {
      parseSWF_RGBA (f, &parserrec->TextColor);
    }
  if (parserrec->HasMaxLength)
    {
      parserrec->MaxLength = readUInt16 (f);
    }
  if (parserrec->HasLayout)
    {
      parserrec->Align = readUInt8 (f);
      parserrec->LeftMargin = readUInt16 (f);
      parserrec->RightMargin = readUInt16 (f);
      parserrec->Indent = readUInt16 (f);
      parserrec->Leading = readUInt16 (f);
    }
  parserrec->VariableName = readString (f);
  if (parserrec->HasText)
    {
      parserrec->InitialText = readString (f);
    }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEFONT (FILE * f, int length)
{
  int i;
  UI16  firstOffset;
  PAR_BEGIN (SWF_DEFINEFONT);

  parserrec->FontID = readUInt16 (f);
  firstOffset = readUInt16 (f);
  parserrec->NumGlyphs = (firstOffset/2);
  Movie_addFontInfo(&m, parserrec->FontID, parserrec->NumGlyphs);
  parserrec->OffsetTable = (UI16 *)malloc((firstOffset/2) * sizeof( UI16 ) );
  parserrec->OffsetTable[0] = firstOffset;
  for(i=1;i<firstOffset/2;i++) {
  	parserrec->OffsetTable[i] = readUInt16 (f);
  }
  parserrec->GlyphShapeTable = (SWF_SHAPE *)malloc(firstOffset/2 * sizeof( SWF_SHAPE ) );
  for(i=0;i<firstOffset/2;i++) {
    int len;
    if(i < firstOffset/2 - 1)
      len = parserrec->OffsetTable[i + 1] - parserrec->OffsetTable[i];
    else
      len = length -  parserrec->OffsetTable[i];
    parseSWF_SHAPE(f, &(parserrec->GlyphShapeTable[i]), 1, len);
  }
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEFONT2 (FILE * f, int length)
{
  int i;
  PAR_BEGIN (SWF_DEFINEFONT2);

  byteAlign ();

  parserrec->FontID = readUInt16 (f);
  parserrec->FontFlagsHasLayout = readBits (f, 1);
  parserrec->FontFlagsShiftJis = readBits (f, 1);
  parserrec->FontFlagsSmallText = readBits (f, 1);
  parserrec->FontFlagsFlagANSI = readBits (f, 1);
  parserrec->FontFlagsWideOffsets = readBits (f, 1);
  parserrec->FontFlagsWideCodes = readBits (f, 1);
  parserrec->FontFlagsFlagsItalics = readBits (f, 1);
  parserrec->FontFlagsFlagsBold = readBits (f, 1);
  parserrec->LanguageCode = readUInt8 (f);
  parserrec->FontNameLen = readUInt8 (f);
  parserrec->FontName = readSizedString (f, parserrec->FontNameLen);
  parserrec->NumGlyphs = readUInt16 (f);
  Movie_addFontInfo(&m, parserrec->FontID, parserrec->NumGlyphs);
  if (parserrec->FontFlagsWideOffsets)
    {
      parserrec->OffsetTable.UI32 =
	(UI32 *) malloc (parserrec->NumGlyphs * sizeof (UI32));
      for (i = 0; i < parserrec->NumGlyphs; i++)
	{
	  parserrec->OffsetTable.UI32[i] = readUInt32 (f);
	}
    }
  else
    {
      parserrec->OffsetTable.UI16 =
	(UI16 *) malloc (parserrec->NumGlyphs * sizeof (UI16));
      for (i = 0; i < parserrec->NumGlyphs; i++)
	{
	  parserrec->OffsetTable.UI16[i] = readUInt16 (f);
	}
    }

  if (parserrec->FontFlagsWideOffsets)
    {
	parserrec->CodeTableOffset.UI32 = readUInt32 (f);
    }
  else
    {
	parserrec->CodeTableOffset.UI16 = readUInt16 (f);
    }

  parserrec->GlyphShapeTable = (SWF_SHAPE *)
    malloc (parserrec->NumGlyphs * sizeof (SWF_SHAPE));
  for (i = 0; i < parserrec->NumGlyphs; i++)
    {
      int len;
      if(parserrec->FontFlagsWideOffsets)
      {
        if(i < parserrec->NumGlyphs - 1)
          len = parserrec->OffsetTable.UI32[i + 1] - parserrec->OffsetTable.UI32[i];
        else
          len = parserrec->CodeTableOffset.UI32 - parserrec->OffsetTable.UI32[i];   
      }
      else
      {
         if(i < parserrec->NumGlyphs - 1)
           len = parserrec->OffsetTable.UI16[i + 1] - parserrec->OffsetTable.UI16[i];
         else
           len = parserrec->CodeTableOffset.UI16 - parserrec->OffsetTable.UI16[i];
      }
	parseSWF_SHAPE (f, parserrec->GlyphShapeTable + i, 3, len);
    }

  parserrec->CodeTable =
	(int *) malloc (parserrec->NumGlyphs * sizeof (int));
  if (parserrec->FontFlagsWideCodes)
    {
      for (i = 0; i < parserrec->NumGlyphs; i++)
	{
	  parserrec->CodeTable[i] = readUInt16 (f);
	}
    }
  else
    {
      for (i = 0; i < parserrec->NumGlyphs; i++)
	{
	  parserrec->CodeTable[i] = readUInt8 (f);
	}
    }

  if( parserrec->FontFlagsHasLayout ) {
	  parserrec->FontAscent = readSInt16(f);
	  parserrec->FontDecent = readSInt16(f);
	  parserrec->FontLeading = readSInt16(f);
	  /* FontAdvanceTable */
	  parserrec->FontAdvanceTable =
	     (SI16 *) malloc (parserrec->NumGlyphs * sizeof (SI16));
	  for (i = 0; i < parserrec->NumGlyphs; i++)
	  {
	    parserrec->FontAdvanceTable[i] = readSInt16 (f);
	  }
	  /* FontBoundsTable */
	  parserrec->FontBoundsTable =
	     (SWF_RECT *) malloc (parserrec->NumGlyphs * sizeof (SWF_RECT));
	  for (i = 0; i < parserrec->NumGlyphs; i++)
	  {
	    parseSWF_RECT (f, &(parserrec->FontBoundsTable[i]));
	  }
	  parserrec->KerningCount = readUInt16(f);
	  /* FontKerningTable */
	  parserrec->FontKerningTable =
	     (struct SWF_KERNINGRECORD *) malloc (parserrec->KerningCount * sizeof (struct SWF_KERNINGRECORD));
	  for (i = 0; i < parserrec->KerningCount; i++)
	  {
	    if( parserrec->FontFlagsWideCodes ) {
		parserrec->FontKerningTable[i].FontKerningCode1 = readUInt16 (f);
		parserrec->FontKerningTable[i].FontKerningCode2 = readUInt16 (f);
	    } else {
		parserrec->FontKerningTable[i].FontKerningCode1 = readUInt8 (f);
		parserrec->FontKerningTable[i].FontKerningCode2 = readUInt8 (f);
	    }
	    parserrec->FontKerningTable[i].FontKerningAdjustment = readSInt16 (f);
	  }
  }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEFONT3 (FILE * f, int length)
{
  int i;
  PAR_BEGIN (SWF_DEFINEFONT3);

  byteAlign ();

  parserrec->FontID = readUInt16 (f);
  parserrec->FontFlagsHasLayout = readBits (f, 1);
  parserrec->FontFlagsShiftJis = readBits (f, 1);
  parserrec->FontFlagsSmallText = readBits (f, 1);
  parserrec->FontFlagsFlagANSI = readBits (f, 1);
  parserrec->FontFlagsWideOffsets = readBits (f, 1);
  parserrec->FontFlagsWideCodes = readBits (f, 1);
  parserrec->FontFlagsFlagsItalics = readBits (f, 1);
  parserrec->FontFlagsFlagsBold = readBits (f, 1);
  parserrec->LanguageCode = readUInt8 (f);
  parserrec->FontNameLen = readUInt8 (f);
  parserrec->FontName = readSizedString (f, parserrec->FontNameLen);
  parserrec->NumGlyphs = readUInt16 (f);
  Movie_addFontInfo(&m, parserrec->FontID, parserrec->NumGlyphs);
  if (parserrec->FontFlagsWideOffsets)
    {
      parserrec->OffsetTable.UI32 =
	(UI32 *) malloc (parserrec->NumGlyphs * sizeof (UI32));
      for (i = 0; i < parserrec->NumGlyphs; i++)
	{
	  parserrec->OffsetTable.UI32[i] = readUInt32 (f);
	}
    }
  else
    {
      parserrec->OffsetTable.UI16 =
	(UI16 *) malloc (parserrec->NumGlyphs * sizeof (UI16));
      for (i = 0; i < parserrec->NumGlyphs; i++)
	{
	  parserrec->OffsetTable.UI16[i] = readUInt16 (f);
	}
    }

  if (parserrec->FontFlagsWideOffsets)
    {
	parserrec->CodeTableOffset.UI32 = readUInt32 (f);
    }
  else
    {
	parserrec->CodeTableOffset.UI16 = readUInt16 (f);
    }

  parserrec->GlyphShapeTable = (SWF_SHAPE *)
    malloc (parserrec->NumGlyphs * sizeof (SWF_SHAPE));
  for (i = 0; i < parserrec->NumGlyphs; i++)
    {
      int len;
      if(parserrec->FontFlagsWideOffsets)
      {
        if(i < parserrec->NumGlyphs - 1)
          len = parserrec->OffsetTable.UI32[i + 1] - parserrec->OffsetTable.UI32[i];
        else
          len = parserrec->CodeTableOffset.UI32 - parserrec->OffsetTable.UI32[i];   
      }
      else
      {
         if(i < parserrec->NumGlyphs - 1)
           len = parserrec->OffsetTable.UI16[i + 1] - parserrec->OffsetTable.UI16[i];
         else
           len = parserrec->CodeTableOffset.UI16 - parserrec->OffsetTable.UI16[i];
      }
      parseSWF_SHAPE (f, &parserrec->GlyphShapeTable[i], 3, len);
    }

  parserrec->CodeTable =
	(UI16 *) malloc (parserrec->NumGlyphs * sizeof (UI16));
  if (parserrec->FontFlagsWideCodes)
    {
      for (i = 0; i < parserrec->NumGlyphs; i++)
	{
	  parserrec->CodeTable[i] = readUInt16 (f);
	}
    }
  else
    {
      for (i = 0; i < parserrec->NumGlyphs; i++)
	{
	  parserrec->CodeTable[i] = readUInt8 (f);
	}
    }

  if( parserrec->FontFlagsHasLayout ) {
	  parserrec->FontAscent = readSInt16(f);
	  parserrec->FontDecent = readSInt16(f);
	  parserrec->FontLeading = readSInt16(f);
	  /* FontAdvanceTable */
	  parserrec->FontAdvanceTable =
	     (SI16 *) malloc (parserrec->NumGlyphs * sizeof (SI16));
	  for (i = 0; i < parserrec->NumGlyphs; i++)
	  {
	    parserrec->FontAdvanceTable[i] = readSInt16 (f);
	  }
	  /* FontBoundsTable */
	  parserrec->FontBoundsTable =
	     (SWF_RECT *) malloc (parserrec->NumGlyphs * sizeof (SWF_RECT));
	  for (i = 0; i < parserrec->NumGlyphs; i++)
	  {
	    parseSWF_RECT (f, &(parserrec->FontBoundsTable[i]));
	  }
	  parserrec->KerningCount = readUInt16(f);
	  /* FontKerningTable */
	  parserrec->FontKerningTable =
	     (struct SWF_KERNINGRECORD *) malloc (parserrec->KerningCount * sizeof (struct SWF_KERNINGRECORD));
	  for (i = 0; i < parserrec->KerningCount; i++)
	  {
	    if( parserrec->FontFlagsWideCodes ) {
		parserrec->FontKerningTable[i].FontKerningCode1 = readUInt16 (f);
		parserrec->FontKerningTable[i].FontKerningCode2 = readUInt16 (f);
	    } else {
		parserrec->FontKerningTable[i].FontKerningCode1 = readUInt8 (f);
		parserrec->FontKerningTable[i].FontKerningCode2 = readUInt8 (f);
	    }
	    parserrec->FontKerningTable[i].FontKerningAdjustment = readSInt16 (f);
	  }
  }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEFONTINFO (FILE * f, int length)
{
  int i, end = fileOffset + length;
  PAR_BEGIN (SWF_DEFINEFONTINFO);

  parserrec->FontID = readUInt16 (f);
  parserrec->FontNameLen = readUInt8 (f);
  parserrec->FontName = readSizedString (f, parserrec->FontNameLen);
  byteAlign ();
  parserrec->FontFlagsReserved = readBits (f, 2);
  parserrec->FontFlagsSmallText = readBits (f, 1);
  parserrec->FontFlagsShiftJIS = readBits (f, 1);
  parserrec->FontFlagsANSI = readBits (f, 1);
  parserrec->FontFlagsItalic = readBits (f, 1);
  parserrec->FontFlagsBold = readBits (f, 1);
  parserrec->FontFlagsWideCodes = readBits (f, 1);
  if( parserrec->FontFlagsWideCodes )
	  parserrec->nGlyph = (end-fileOffset)/2;
  else
	  parserrec->nGlyph = end-fileOffset;

  parserrec->CodeTable = (UI16 *)malloc(parserrec->nGlyph*sizeof(UI16));
  for(i=0;i<parserrec->nGlyph;i++)
  if( parserrec->FontFlagsWideCodes )
	  parserrec->CodeTable[i] = readUInt16(f);
  else
	  parserrec->CodeTable[i] = readUInt8(f);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEFONTINFO2 (FILE * f, int length)
{
  int i, end = fileOffset + length;
  PAR_BEGIN (SWF_DEFINEFONTINFO2);

  parserrec->FontID = readUInt16 (f);
  parserrec->FontNameLen = readUInt8 (f);
  parserrec->FontName = readSizedString (f, parserrec->FontNameLen);
  byteAlign ();
  parserrec->FontFlagsReserved = readBits (f, 2);
  parserrec->FontFlagsSmallText = readBits (f, 1);
  parserrec->FontFlagsShiftJIS = readBits (f, 1);
  parserrec->FontFlagsANSI = readBits (f, 1);
  parserrec->FontFlagsItalic = readBits (f, 1);
  parserrec->FontFlagsBold = readBits (f, 1);
  parserrec->FontFlagsWideCodes = readBits (f, 1);
  parserrec->LanguageCode = readUInt8(f);
  parserrec->nGlyph = (end-fileOffset)/2;

  parserrec->CodeTable = (UI16 *)malloc(parserrec->nGlyph*sizeof(UI16));
  for(i=0;i<parserrec->nGlyph;i++)
	  parserrec->CodeTable[i] = readUInt16(f);
  
  PAR_END;
}

SWF_Parserstruct *
parseSWF_CSMTEXTSETTINGS (FILE * f, int length)
{ 
  PAR_BEGIN (SWF_CSMTEXTSETTINGS);
  parserrec->TextID = readUInt16(f);
  parserrec->UseFlashType = readBits(f, 2);
  parserrec->GridFit = readBits(f, 3);
  parserrec->Reserved = readBits(f, 3);
  parserrec->Thickness = readUInt32(f); 
  parserrec->Sharpness = readUInt32(f);
  parserrec->Reserved = readUInt8(f);
  PAR_END;
}

void 
parseSWF_ZONEDATA(FILE *f, struct SWF_ZONEDATA *data)
{
  data->AlignmentCoordinate = readUInt16(f); // FLOAT16
  data->Range = readUInt16(f); // FLOAT16
}

void 
parseSWF_ZONERECORD(FILE *f, struct SWF_ZONERECORD *table)
{
  int i;
  table->NumZoneData = readUInt8(f);
  table->ZoneData = (struct SWF_ZONEDATA *)
    malloc(table->NumZoneData * sizeof(struct SWF_ZONEDATA));
  for(i = 0; i < table->NumZoneData; i++)
  	parseSWF_ZONEDATA(f, table->ZoneData + i);
  
  table->ZoneMaskX = readBits(f, 1);
  table->ZoneMaskY = readBits(f, 1);
  table->Reserved  = readBits(f, 6);	
}

SWF_Parserstruct *
parseSWF_DEFINEFONTALIGNZONES(FILE *f, int length)
{
  int i;
  PAR_BEGIN (SWF_DEFINEFONTALIGNZONES);
  parserrec->FontID = readUInt16(f);
  parserrec->CSMTableHint = readBits(f, 2);
  parserrec->Reserved = readBits(f, 6);
  parserrec->GlyphCount = Movie_getFontGlyphCount(&m, parserrec->FontID);
  if(parserrec->GlyphCount < 0)
	SWF_error("SWF_DEFINEFONTALIGNZONES: FontID %i not present\n", parserrec->FontID);
  parserrec->ZoneTable = malloc(sizeof(struct SWF_ZONERECORD) * parserrec->GlyphCount);
 
  for(i = 0; i < parserrec->GlyphCount; i++)
  	parseSWF_ZONERECORD(f, parserrec->ZoneTable + i);
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEFONTNAME(FILE * f, int length)
{
  PAR_BEGIN(SWF_DEFINEFONTNAME);
  parserrec->FontId = readUInt16(f);
  parserrec->FontName = readString(f);
  parserrec->FontCopyright = readString(f); 
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINELOSSLESS (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_DEFINELOSSLESS);

  parserrec->CharacterID = readUInt16 (f);
  parserrec->BitmapFormat = readUInt8 (f);
  parserrec->BitmapWidth = readUInt16 (f);
  parserrec->BitmapHeight = readUInt16 (f);
  if( parserrec->BitmapFormat == 3 /* 8-bit */ ) {
      parserrec->BitmapColorTableSize = readUInt8 (f);
  }
  parserrec->ZlibBitmapData = (UI8 *)readBytes (f,end-fileOffset);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINELOSSLESS2 (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_DEFINELOSSLESS2);

  parserrec->CharacterID = readUInt16 (f);
  parserrec->BitmapFormat = readUInt8 (f);
  parserrec->BitmapWidth = readUInt16 (f);
  parserrec->BitmapHeight = readUInt16 (f);
  if( parserrec->BitmapFormat == 3 /* 8-bit */ ) {
      parserrec->BitmapColorTableSize = readUInt8 (f);
  }
  parserrec->ZlibBitmapData = (UI8 *)readBytes (f,end-fileOffset);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEMORPHSHAPE (FILE * f, int length)
{
  int end, endEdges;
  PAR_BEGIN (SWF_DEFINEMORPHSHAPE);
  end = fileOffset + length;
  parserrec->CharacterID = readUInt16 (f);
  parseSWF_RECT (f, &(parserrec->StartBounds));
  parseSWF_RECT (f, &(parserrec->EndBounds));
  
  parserrec->Offset = readUInt32 (f);
  endEdges = fileOffset + parserrec->Offset;

  parseSWF_MORPHFILLSTYLES (f, &(parserrec->MorphFillStyles));
  parseSWF_MORPHLINESTYLES (f, &(parserrec->MorphLineStyles), 1);
  
  if(parserrec->Offset == 0)
    SWF_error("parseSWF_DEFINEMORPHSHAPE: offset == 0!\n");
  
  parseSWF_SHAPE (f, &(parserrec->StartEdges), 0, endEdges - fileOffset);
  parseSWF_SHAPE (f, &(parserrec->EndEdges), 0, end - fileOffset);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEMORPHSHAPE2 (FILE * f, int length)
{
  int end, endEdges;
  PAR_BEGIN (SWF_DEFINEMORPHSHAPE2);
  end = fileOffset + length;
  
  parserrec->CharacterID = readUInt16 (f);
  parseSWF_RECT (f, &(parserrec->StartBounds));
  parseSWF_RECT (f, &(parserrec->EndBounds));
  parseSWF_RECT (f, &(parserrec->StartEdgeBounds));
  parseSWF_RECT (f, &(parserrec->EndEdgeBounds));
  parserrec->Reserved = readBits(f, 6);
  parserrec->UsesNonScalingStrokes = readBits(f, 1);
  parserrec->UsesScalingStrokes = readBits(f, 1);
  
  parserrec->Offset = readUInt32 (f);
  endEdges = fileOffset + parserrec->Offset + 4;
  parseSWF_MORPHFILLSTYLES (f, &(parserrec->MorphFillStyles));
  parseSWF_MORPHLINESTYLES (f, &(parserrec->MorphLineStyles), 2);
  
  if(parserrec->Offset == 0)
    SWF_error("parseSWF_DEFINEMORPHSHAPE2: offset == 0!\n");
  
  parseSWF_SHAPE (f, &(parserrec->StartEdges), 0, endEdges - fileOffset);
  parseSWF_SHAPE (f, &(parserrec->EndEdges), 0, end - fileOffset);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINESHAPE (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINESHAPE);

  parserrec->ShapeID = readUInt16 (f);
  parseSWF_RECT (f, &(parserrec->ShapeBounds));
  parseSWF_SHAPEWITHSTYLE (f, &(parserrec->Shapes), 1);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINESHAPE2 (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINESHAPE2);

  parserrec->ShapeID = readUInt16 (f);
  parseSWF_RECT (f, &(parserrec->ShapeBounds));
  parseSWF_SHAPEWITHSTYLE (f, &(parserrec->Shapes), 2);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINESHAPE3 (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINESHAPE3);

  parserrec->ShapeID = readUInt16 (f);
  parseSWF_RECT (f, &(parserrec->ShapeBounds));
  parseSWF_SHAPEWITHSTYLE (f, &(parserrec->Shapes), 3);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINESHAPE4 (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINESHAPE4);

  parserrec->ShapeID = readUInt16 (f);
  parseSWF_RECT (f, &(parserrec->ShapeBounds));
  parseSWF_RECT (f, &(parserrec->EdgeBounds));
  parserrec->Reserved = readBits(f, 6);
  parserrec->UsesNonScalingStrokes = readBits(f, 1);
  parserrec->UsesScalingStrokes = readBits(f, 1);
  parseSWF_SHAPEWITHSTYLE (f, &(parserrec->Shapes), 4);

  PAR_END;
}


SWF_Parserstruct *
parseSWF_DEFINESPRITE (FILE * f, int length)
{
  int block, type, splength, blockstart, nextFrame;
  int numblocks, start;
  PAR_BEGIN (SWF_DEFINESPRITE);

  numblocks=0;
  start = fileOffset;
  parserrec->SpriteId = readUInt16 (f);
  parserrec->FrameCount = readUInt16 (f);
  parserrec->tagTypes = NULL;
  parserrec->Tags = NULL;
  while( fileOffset < start+length ) {
	  /*
	  printf ("Block offset: %d\n", fileOffset);
	  */
	  block = readUInt16 (f);
	  type = block >> 6;
	  splength = block & ((1 << 6) - 1);
	  if (splength == 63)         /* it's a long block. */
		    splength = readUInt32 (f);
	  blockstart = fileOffset;
	  nextFrame = fileOffset+splength;
          /*
	  printf ("Found Block: %s, %i bytes @%i\n",
			  blockName (type), splength, blockstart );
          */
	  parserrec->tagTypes = (UI16 *)
	  	realloc(parserrec->tagTypes, ((numblocks+1)*sizeof(UI16)));
	  parserrec->Tags = (SWF_Parserstruct **)
	  	realloc(parserrec->Tags,
				((numblocks+1)*sizeof(SWF_Parserstruct *)));

	  parserrec->tagTypes[numblocks] = type;
	  parserrec->Tags[numblocks++]=blockParse(f,splength,type);
	  if( ftell(f) != nextFrame ) {
	    SWF_warn(" Sprite Stream out of sync...\n");
	    SWF_warn(" %ld but expecting %d\n", ftell(f),nextFrame);
	    fseek(f,blockstart,SEEK_SET);
	    silentSkipBytes (f, (nextFrame-ftell(f)));
	    fileOffset=ftell(f);
	  }
	  if(type == 0)
		break;
  }
  if(fileOffset < start + length)
  {  
    SWF_warn("PARSER: parseSWF_DEFINESPRITE (ID %i): skiping excessive bytes after SWF_END.\n", 
	parserrec->SpriteId);
    readBytes(f, start + length - fileOffset);
  } 
  parserrec->BlockCount = numblocks;

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINETEXT (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINETEXT);

  parserrec->CharacterID = readUInt16 (f);
  parseSWF_RECT (f, &(parserrec->TextBounds));
  parseSWF_MATRIX (f, &(parserrec->TextMatrix));
  parserrec->GlyphBits = readUInt8 (f);
  parserrec->AdvanceBits = readUInt8 (f);

  parserrec->TextRecords =
    (SWF_TEXTRECORD *) calloc (1, sizeof (SWF_TEXTRECORD));
  parserrec->numTextRecords = 0;
  while ( parseSWF_TEXTRECORD (f, &(parserrec->TextRecords[parserrec->numTextRecords++]), parserrec->GlyphBits, parserrec->AdvanceBits, 1 ) ) {
      parserrec->TextRecords = (SWF_TEXTRECORD *) realloc (parserrec->TextRecords,
							 (parserrec->
							  numTextRecords +
							  1) *
							 sizeof
							 (SWF_TEXTRECORD));
    }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINETEXT2 (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINETEXT2);

  parserrec->CharacterID = readUInt16 (f);
  parseSWF_RECT (f, &(parserrec->TextBounds));
  parseSWF_MATRIX (f, &(parserrec->TextMatrix));
  parserrec->GlyphBits = readUInt8 (f);
  parserrec->AdvanceBits = readUInt8 (f);

  parserrec->TextRecords =
    (SWF_TEXTRECORD *) calloc (1, sizeof (SWF_TEXTRECORD));
  parserrec->numTextRecords = 0;
  while ( parseSWF_TEXTRECORD (f, &(parserrec->TextRecords[parserrec->numTextRecords++]), parserrec->GlyphBits, parserrec->AdvanceBits, 2 ) ) {
      parserrec->TextRecords = (SWF_TEXTRECORD *) realloc (parserrec->TextRecords,
							 (parserrec->
							  numTextRecords +
							  1) *
							 sizeof
							 (SWF_TEXTRECORD));
    }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINETEXTFORMAT (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINETEXTFORMAT);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEVIDEO (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINEVIDEO);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEVIDEOSTREAM (FILE * f, int length)
{
  PAR_BEGIN (SWF_DEFINEVIDEOSTREAM);
  
  parserrec->CharacterID = readUInt16 (f);
  parserrec->NumFrames = readUInt16(f);
  parserrec->Width = readUInt16(f);
  parserrec->Height = readUInt16(f);
  byteAlign ();
  parserrec->Reserved = readBits (f, 5);
  parserrec->VideoFlagsDeblocking = readBits (f, 2);
  parserrec->VideoFlagsSmoothing = readBits(f, 1);
  parserrec->CodecID = readUInt8(f);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_DOACTION (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_DOACTION);

  parserrec->Actions =
    (SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
  parserrec->numActions = 0;
  while ( fileOffset < end ) {
      parseSWF_ACTIONRECORD (f, &(parserrec->numActions), parserrec->Actions );
      parserrec->Actions = (SWF_ACTION *) realloc (parserrec->Actions,
							 (++parserrec->
							  numActions +
							  1) *
							 sizeof
							 (SWF_ACTION));
    }

  /* parserrec->AScript = decompile5Action (f, length, 1); */

  PAR_END;
}

SWF_Parserstruct *
parseSWF_ENABLEDEBUGGER (FILE * f, int length)
{
  PAR_BEGIN (SWF_ENABLEDEBUGGER);
  parserrec->Password = readString(f); 
  PAR_END;
}

SWF_Parserstruct *
parseSWF_ENABLEDEBUGGER2 (FILE * f, int length)
{
  PAR_BEGIN (SWF_ENABLEDEBUGGER2);
  parserrec->Reserved = readUInt16(f);
  parserrec->Password = readString(f); 
  PAR_END;
}


SWF_Parserstruct *
parseSWF_END (FILE * f, int length)
{
  PAR_BEGIN (SWF_END);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_EXPORTASSETS (FILE * f, int length)
{
  int i;
  PAR_BEGIN (SWF_EXPORTASSETS);

  parserrec->Count = readUInt16 (f);
  parserrec->Tags = (UI16 *)malloc(parserrec->Count*sizeof(UI16));
  parserrec->Names = (STRING *)malloc(parserrec->Count*sizeof(char *));
  for(i=0;i<parserrec->Count;i++) {
	parserrec->Tags[i] = readUInt16(f);
	parserrec->Names[i] = readString(f);
  }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_FONTREF (FILE * f, int length)
{
  PAR_BEGIN (SWF_FONTREF);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_FRAMELABEL (FILE * f, int length)
{
  PAR_BEGIN (SWF_FRAMELABEL);

  parserrec->Name = readString (f);

  // SWF6 named anchor
  if ( strlen(parserrec->Name)+1 == length-1 )
  {
    parserrec->IsAnchor = readUInt8(f); 
  }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_FRAMETAG (FILE * f, int length)
{
  PAR_BEGIN (SWF_FRAMETAG);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_FREEALL (FILE * f, int length)
{
  PAR_BEGIN (SWF_FREEALL);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_FREECHARACTER (FILE * f, int length)
{
  PAR_BEGIN (SWF_FREECHARACTER); 
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_GENCOMMAND (FILE * f, int length)
{
  PAR_BEGIN (SWF_GENCOMMAND);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_IMPORTASSETS (FILE * f, int length)
{
  int i;
  PAR_BEGIN (SWF_IMPORTASSETS);

  parserrec->URL = readString (f);
  parserrec->Count = readUInt16 (f);
  parserrec->Tags = (UI16 *)malloc(parserrec->Count*sizeof(UI16));
  parserrec->Names = (STRING *)malloc(parserrec->Count*sizeof(char *));
  for(i=0;i<parserrec->Count;i++) {
	parserrec->Tags[i] = readUInt16(f);
	parserrec->Names[i] = readString(f);
  }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_IMPORTASSETS2 (FILE * f, int length)
{
  int i;
  PAR_BEGIN (SWF_IMPORTASSETS2);

  parserrec->URL = readString (f);
  parserrec->Reserved = readUInt8(f);
  parserrec->Reserved2 = readUInt8(f);
  parserrec->Count = readUInt16 (f);
  parserrec->Tags = (UI16 *)malloc(parserrec->Count*sizeof(UI16));
  parserrec->Names = (STRING *)malloc(parserrec->Count*sizeof(char *));
  for(i=0;i<parserrec->Count;i++) {
	parserrec->Tags[i] = readUInt16(f);
	parserrec->Names[i] = readString(f);
  }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_JPEGTABLES (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_JPEGTABLES);

  parserrec->JPEGDataSize = end-fileOffset;
  parserrec->JPEGData = (UI8 *)readBytes(f,end-fileOffset);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_NAMECHARACTER (FILE * f, int length)
{
  PAR_BEGIN (SWF_NAMECHARACTER);
  parserrec->Id = readUInt16(f);
  parserrec->Name = readString(f);
  PAR_END;
}

SWF_Parserstruct *
parseSWF_PATHSAREPOSTSCRIPT (FILE * f, int length)
{
  PAR_BEGIN (SWF_PATHSAREPOSTSCRIPT);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_PLACEOBJECT (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_PLACEOBJECT);
  
  parserrec->CharacterId = readUInt16 (f);
  parserrec->Depth = readUInt16 (f);
  parseSWF_MATRIX( f, &(parserrec->Matrix) );

  if(end > fileOffset)
    parseSWF_CXFORMWITHALPHA( f, &(parserrec->ColorTransform) ); 
	
  PAR_END;
}

SWF_Parserstruct *
parseSWF_PLACEOBJECT2 (FILE * f, int length)
{
  PAR_BEGIN (SWF_PLACEOBJECT2);

  byteAlign();
  int end = fileOffset + length;
  parserrec->PlaceFlagHasClipActions = readBits (f, 1);
  parserrec->PlaceFlagHasClipDepth   = readBits (f, 1);
  parserrec->PlaceFlagHasName        = readBits (f, 1);
  parserrec->PlaceFlagHasRatio       = readBits (f, 1);
  parserrec->PlaceFlagHasColorTransform = readBits (f, 1);
  parserrec->PlaceFlagHasMatrix      = readBits (f, 1);
  parserrec->PlaceFlagHasCharacter   = readBits (f, 1);
  parserrec->PlaceFlagMove           = readBits (f, 1);
  parserrec->Depth = readUInt16 (f);
  if( parserrec->PlaceFlagHasCharacter ) {
    parserrec->CharacterId = readUInt16 (f);
  }
  if( parserrec->PlaceFlagHasMatrix ) {
    parseSWF_MATRIX( f, &(parserrec->Matrix) ); 
  }
  if( parserrec->PlaceFlagHasColorTransform ) {
    parseSWF_CXFORMWITHALPHA( f, &(parserrec->ColorTransform) ); 
  }
  if( parserrec->PlaceFlagHasRatio ) {
    parserrec->Ratio = readUInt16 (f);
  }
  if( parserrec->PlaceFlagHasName ) {
    parserrec->Name = readString (f);
  }
  if( parserrec->PlaceFlagHasClipDepth ) {
    parserrec->ClipDepth = readUInt16 (f);
  }
  if( parserrec->PlaceFlagHasClipActions ) {
    parseSWF_CLIPACTIONS( f, &(parserrec->ClipActions), end); 
  }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_PLACEOBJECT3 (FILE * f, int length)
{
  PAR_BEGIN (SWF_PLACEOBJECT3);

  byteAlign();
  int end = fileOffset + length;
  parserrec->PlaceFlagHasClipActions = readBits (f, 1);
  parserrec->PlaceFlagHasClipDepth   = readBits (f, 1);
  parserrec->PlaceFlagHasName        = readBits (f, 1);
  parserrec->PlaceFlagHasRatio       = readBits (f, 1);
  parserrec->PlaceFlagHasColorTransform = readBits (f, 1);
  parserrec->PlaceFlagHasMatrix      = readBits (f, 1);
  parserrec->PlaceFlagHasCharacter   = readBits (f, 1);
  parserrec->PlaceFlagMove           = readBits (f, 1);
  
  byteAlign();
  parserrec->Reserved                = readBits (f, 3);
  parserrec->PlaceFlagHasImage       = readBits (f, 1);
  parserrec->PlaceFlagHasClassName   = readBits (f, 1);
  parserrec->PlaceFlagHasCacheAsBitmap = readBits (f, 1);
  parserrec->PlaceFlagHasBlendMode   = readBits(f, 1);
  parserrec->PlaceFlagHasFilterList  = readBits(f, 1);

  parserrec->Depth = readUInt16 (f);
  if( parserrec->PlaceFlagHasCharacter ) {
    parserrec->CharacterId = readUInt16 (f);
  }
 
  if(parserrec->PlaceFlagHasClassName || 
      (parserrec->PlaceFlagHasImage && parserrec->PlaceFlagHasCharacter))
  {
    parserrec->ClassName = readString(f);
  }

  if( parserrec->PlaceFlagHasMatrix ) {
    parseSWF_MATRIX( f, &(parserrec->Matrix) ); 
  }
  if( parserrec->PlaceFlagHasColorTransform ) {
    parseSWF_CXFORMWITHALPHA( f, &(parserrec->ColorTransform) ); 
  }
  if( parserrec->PlaceFlagHasRatio ) {
    parserrec->Ratio = readUInt16 (f);
  }
  if( parserrec->PlaceFlagHasName ) {
    parserrec->Name = readString (f);
  }
  if( parserrec->PlaceFlagHasClipDepth ) {
    parserrec->ClipDepth = readUInt16 (f);
  }
  if( parserrec->PlaceFlagHasFilterList ) {
    parseSWF_FILTERLIST( f, &parserrec->SurfaceFilterList);
  }
  if( parserrec->PlaceFlagHasBlendMode ) {
    parserrec->BlendMode = readUInt8 (f);
  }
  if( parserrec->PlaceFlagHasClipActions ) {
    parseSWF_CLIPACTIONS( f, &(parserrec->ClipActions), end); 
  }
   
  PAR_END;
}

SWF_Parserstruct *
parseSWF_PREBUILT (FILE * f, int length)
{
  PAR_BEGIN (SWF_PREBUILT);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_PREBUILTCLIP (FILE * f, int length)
{
  PAR_BEGIN (SWF_PREBUILTCLIP);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_PROTECT (FILE * f, int length)
{
  PAR_BEGIN (SWF_PROTECT);

  if( length != 0 ) {
  	parserrec->Password = readBytes (f, length);
  } else {
  	parserrec->Password = NULL;
  }

  PAR_END;
}

SWF_Parserstruct *
parseSWF_REMOVEOBJECT (FILE * f, int length)
{
  PAR_BEGIN (SWF_REMOVEOBJECT);

  parserrec->CharacterId = readUInt16 (f);
  parserrec->Depth = readUInt16 (f);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_REMOVEOBJECT2 (FILE * f, int length)
{
  PAR_BEGIN (SWF_REMOVEOBJECT2);

  parserrec->Depth = readUInt16 (f);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_SERIALNUMBER (FILE * f, int length)
{
  PAR_BEGIN (SWF_SERIALNUMBER);
  parserrec->Id = readUInt32(f);
  parserrec->Edition = readUInt32(f);
  parserrec->Major = readUInt8(f);
  parserrec->Minor = readUInt8(f);
  parserrec->BuildL = readUInt32(f);
  parserrec->BuildH = readUInt32(f);
  parserrec->TimestampL = readUInt32(f);
  parserrec->TimestampH = readUInt32(f);
  PAR_END;
}

SWF_Parserstruct *
parseSWF_SETBACKGROUNDCOLOR (FILE * f, int length)
{
  PAR_BEGIN (SWF_SETBACKGROUNDCOLOR);

  parseSWF_RGB (f, &parserrec->rgb);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_SHOWFRAME (FILE * f, int length)
{
  PAR_BEGIN (SWF_SHOWFRAME);

  PAR_END;
}

static inline void 
parseMp3Stream(FILE *f, struct MP3STREAMSOUNDDATA *data, int blockEnd)
{
  data->SampleCount = readUInt16(f);
  data->SeekSamples = readSInt16(f);
  data->frames = (UI8 *)readBytes(f, blockEnd - fileOffset);
}

SWF_Parserstruct *
parseSWF_SOUNDSTREAMBLOCK (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_SOUNDSTREAMBLOCK);
  switch(m.soundStreamFmt)
  {
    case 2:
      parseMp3Stream(f, &parserrec->StreamData.mp3, end);
      break;
    default:
      parserrec->StreamData.data = (UI8 *)readBytes(f, end - fileOffset);
  }
  PAR_END;
}

SWF_Parserstruct *
parseSWF_SOUNDSTREAMHEAD (FILE * f, int length)
{
  PAR_BEGIN (SWF_SOUNDSTREAMHEAD);

  byteAlign ();
  parserrec->Reserved = readBits (f, 4);
  parserrec->PlaybackSoundRate = readBits (f, 2);
  parserrec->PlaybackSoundSize = readBits (f, 1);
  parserrec->PlaybackSoundType = readBits (f, 1);
  parserrec->StreamSoundCompression = readBits (f, 4);
  parserrec->StreamSoundRate = readBits (f, 2);
  parserrec->StreamSoundSize = readBits (f, 1);
  parserrec->StreamSoundType = readBits (f, 1);
  parserrec->StreamSoundSampleCount = readUInt16 (f);
  if( parserrec->StreamSoundCompression == 2 /* MP3 */ )
    parserrec->LatencySeek = readUInt16 (f);
  m.soundStreamFmt = parserrec->StreamSoundCompression;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_SOUNDSTREAMHEAD2 (FILE * f, int length)
{
  PAR_BEGIN (SWF_SOUNDSTREAMHEAD2);

  byteAlign ();
  parserrec->Reserved = readBits (f, 4);
  parserrec->PlaybackSoundRate = readBits (f, 2);
  parserrec->PlaybackSoundSize = readBits (f, 1);
  parserrec->PlaybackSoundType = readBits (f, 1);
  parserrec->StreamSoundCompression = readBits (f, 4);
  parserrec->StreamSoundRate = readBits (f, 2);
  parserrec->StreamSoundSize = readBits (f, 1);
  parserrec->StreamSoundType = readBits (f, 1);
  parserrec->StreamSoundSampleCount = readUInt16 (f);
  if( parserrec->StreamSoundCompression == 2 /* MP3 */ )
    parserrec->LatencySeek = readUInt16 (f);
  m.soundStreamFmt = parserrec->StreamSoundCompression;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINESOUND (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_DEFINESOUND);

  parserrec->SoundId = readUInt16 (f);
  parserrec->SoundFormat = readBits (f, 4);
  parserrec->SoundRate = readBits (f, 2);
  parserrec->SoundSize = readBits (f, 1);
  parserrec->SoundType = readBits (f, 1);
  byteAlign ();
  parserrec->SoundSampleCount = readUInt32 (f);
  
  switch(parserrec->SoundFormat)
  {
    case 2:
      parserrec->SoundData.mp3.SeekSamples = readSInt16(f);
      parserrec->SoundData.mp3.frames = (UI8 *)readBytes(f, end - fileOffset);
      break;
    default:
      parserrec->SoundData.data = (UI8 *)readBytes(f, end - fileOffset);
  }
  PAR_END;
}

void parseSWF_SOUNDINFO(FILE *f, struct SWF_SOUNDINFO *si)
{
  int i;
  
  si->Reserved = readBits (f, 2);
  si->SyncStop = readBits (f, 1);
  si->SyncNoMultiple = readBits (f, 1);
  si->HasEnvelope = readBits (f, 1);
  si->HasLoops = readBits (f, 1);
  si->HasOutPoint = readBits (f, 1);
  si->HasInPoint = readBits (f, 1);
  if( si->HasInPoint )
    si->InPoint = readUInt32 (f);
  if( si->HasOutPoint )
    si->OutPoint = readUInt32 (f);
  if( si->HasLoops )
    si->LoopCount = readUInt16 (f);
  if( si->HasEnvelope ) {
    si->EnvPoints = readUInt8 (f);
    si->EnvelopeRecords =
    (SWF_SOUNDENVELOPE *) calloc (si->EnvPoints, sizeof (SWF_SOUNDENVELOPE));
    for(i=0;i<si->EnvPoints;i++) {
    	si->EnvelopeRecords[i].Pos44 = readUInt32 (f);
    	si->EnvelopeRecords[i].LeftLevel = readUInt16 (f);
    	si->EnvelopeRecords[i].RightLevel = readUInt16 (f);
    	}
    }
}

SWF_Parserstruct *
parseSWF_STARTSOUND (FILE * f, int length)
{
  PAR_BEGIN (SWF_STARTSOUND);
 
  parserrec->SoundId = readUInt16 (f);
  parseSWF_SOUNDINFO(f, &parserrec->SoundInfo);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_STARTSOUND2 (FILE * f, int length)
{
  PAR_BEGIN (SWF_STARTSOUND2);
 
  parserrec->SoundClassName = readString (f);
  parseSWF_SOUNDINFO(f, &parserrec->SoundInfo);

  PAR_END;
}

SWF_Parserstruct *
parseSWF_SYNCFRAME (FILE * f, int length)
{
  PAR_BEGIN (SWF_SYNCFRAME);
  SKIP;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_INITACTION (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_INITACTION);

  parserrec->SpriteId = readUInt16 (f);
  parserrec->Actions =
    (SWF_ACTION *) calloc (1, sizeof (SWF_ACTION));
  parserrec->numActions = 0;
  while ( fileOffset < end ) {
      parseSWF_ACTIONRECORD (f, &(parserrec->numActions), parserrec->Actions);
      parserrec->Actions = (SWF_ACTION *) realloc (parserrec->Actions,
							 (++parserrec->
							  numActions +
							  1) *
							 sizeof
							 (SWF_ACTION));
    }

  /* parserrec->AScript = decompile5Action (f, length, 1); */

  PAR_END;
}

SWF_Parserstruct *
parseSWF_VIDEOFRAME (FILE * f, int length)
{
  int end = fileOffset + length;
  PAR_BEGIN (SWF_VIDEOFRAME);
  parserrec->StreamID = readUInt16 (f);
  parserrec->FrameNum = readUInt16 (f);
  parserrec->VideoData = (UI8 *)readBytes(f, end - fileOffset);
  PAR_END;
}

SWF_Parserstruct *
parseSWF_REFLEX (FILE * f, int length)
{
  PAR_BEGIN (SWF_REFLEX);
  parserrec->rfx[0] = readUInt8 (f);
  parserrec->rfx[1] = readUInt8 (f);
  parserrec->rfx[2] = readUInt8 (f);
  PAR_END;
}

SWF_Parserstruct *
parseSWF_FILEATTRIBUTES (FILE * f, int length)
{
  PAR_BEGIN (SWF_FILEATTRIBUTES);
  byteAlign();
  parserrec->Reserved = readBits(f, 3);
  parserrec->HasMetadata = readBits(f, 1);
  parserrec->ActionScript3 = readBits(f, 1);
  parserrec->Reserved2 = readBits(f, 2);
  parserrec->UseNetwork = readBits(f, 1);
  parserrec->Reserved3 = readUInt16(f);
  parserrec->Reserved4 = readUInt8(f);
  PAR_END;
}

SWF_Parserstruct *
parseSWF_METADATA (FILE * f, int length)
{
  PAR_BEGIN(SWF_METADATA);
  parserrec->Metadata = readString(f);
  PAR_END;
}

SWF_Parserstruct *
parseSWF_SCRIPTLIMITS (FILE * f, int length)
{
  PAR_BEGIN(SWF_SCRIPTLIMITS);
  parserrec->MaxRecursionDepth = readUInt16(f);
  parserrec->ScriptTimeoutSeconds = readUInt16(f);
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINESCALINGGRID (FILE * f, int length)
{
  PAR_BEGIN(SWF_DEFINESCALINGGRID);
  parserrec->CharacterId = readUInt16(f);
  parseSWF_RECT(f, &parserrec->Splitter);  
  PAR_END;
}

SWF_Parserstruct *
parseSWF_SETTABINDEX (FILE * f, int length)
{
  PAR_BEGIN(SWF_SETTABINDEX);
  parserrec->Depth = readUInt16(f);
  parserrec->TabIndex = readUInt16(f);
  PAR_END;
}

void parseABC_STRING_INFO(struct ABC_STRING_INFO *sinfo, FILE *f)
{
  sinfo->Size = readEncUInt30(f);
  sinfo->UTF8String = (UI8 *)readBytes(f, sinfo->Size);
}

void parseABC_NS_INFO(struct ABC_NS_INFO *nsinfo, FILE *f)
{
  nsinfo->Kind = readUInt8(f);
  nsinfo->Name = readEncUInt30(f);
}

void parseABC_NS_SET_INFO(struct ABC_NS_SET_INFO *nsset, FILE *f)
{
  int i;
  nsset->Count = readEncUInt30(f);
  nsset->NS = malloc(sizeof(U30) * nsset->Count);
  for(i = 0; i < nsset->Count; i++)
    nsset->NS[i] = readEncUInt30(f);
}

void parseABC_QNAME(struct ABC_QNAME *qname, FILE *f)
{
  qname->NS = readEncUInt30(f);
  qname->Name = readEncUInt30(f);
}

void parseABC_RTQNAME(struct ABC_RTQNAME *rtq, FILE *f)
{
  rtq->Name = readEncUInt30(f);
}

void parseABC_RTQNAME_L(struct ABC_RTQNAME_L *rtql, FILE *f)
{

}

void parseABC_MULTINAME(struct ABC_MULTINAME *mn, FILE *f)
{
  mn->Name = readEncUInt30(f);
  mn->NSSet = readEncUInt30(f);
}

void parseABC_MULTINAME_L(struct ABC_MULTINAME_L *mnl, FILE *f)
{
  mnl->NSSet = readEncUInt30(f);
}

void parseABC_MULTINAME_INFO(struct ABC_MULTINAME_INFO *minfo, FILE *f)
{
  minfo->Kind = readUInt8(f);
  switch(minfo->Kind)
  {
    case ABC_CONST_QNAME:
    case ABC_CONST_QNAME_A:
      parseABC_QNAME(&minfo->Data.QName, f);
      break;
    case ABC_CONST_RTQNAME:
    case ABC_CONST_RTQNAME_A:
      parseABC_RTQNAME(&minfo->Data.RTQName, f);
      break;
    case ABC_CONST_RTQNAME_L:
    case ABC_CONST_RTQNAME_LA:
      parseABC_RTQNAME_L(&minfo->Data.RTQNameL, f);
      break;
    case ABC_CONST_MULTINAME:
    case ABC_CONST_MULTINAME_A:
      parseABC_MULTINAME(&minfo->Data.Multiname, f);
      break;
    case ABC_CONST_MULTINAME_L:
    case ABC_CONST_MULTINAME_LA:
      parseABC_MULTINAME_L(&minfo->Data.MultinameL, f);
      break;
    default:
      SWF_error("Unknow multiname kind %x\n", minfo->Kind);
  }
}

void parseABC_CONSTANT_POOL(struct ABC_CONSTANT_POOL *cpool, FILE *f)
{
  int i;
  size_t s;
 
  cpool->IntCount = readEncUInt30(f);
  cpool->Integers = malloc(cpool->IntCount * sizeof(S32));
  for(i = 1; i < cpool->IntCount; i++)
      cpool->Integers[i] = readEncSInt32(f);

  cpool->UIntCount = readEncUInt30(f);
  cpool->UIntegers = malloc(cpool->UIntCount * sizeof(U32));
  for(i = 1; i < cpool->UIntCount; i++)
    cpool->UIntegers[i] = readEncUInt32(f);

  cpool->DoubleCount = readEncUInt30(f);
  cpool->Doubles = malloc(cpool->DoubleCount * sizeof(DOUBLE));
  for(i = 1; i < cpool->DoubleCount; i++)
    cpool->Doubles[i] = readDouble(f);

  cpool->StringCount = readEncUInt30(f);
  s = cpool->StringCount * sizeof(struct ABC_STRING_INFO);
  cpool->Strings = malloc(s);
  for(i = 1; i < cpool->StringCount; i++)
    parseABC_STRING_INFO(cpool->Strings + i, f);

  cpool->NamespaceCount = readEncUInt30(f); 
  s = cpool->NamespaceCount * sizeof(struct ABC_NS_INFO);
  cpool->Namespaces = malloc(s);
  for(i = 1; i < cpool->NamespaceCount; i++)
    parseABC_NS_INFO(cpool->Namespaces + i, f);

  cpool->NamespaceSetCount = readEncUInt30(f);
  s = cpool->NamespaceSetCount * sizeof(struct ABC_NS_SET_INFO);
  cpool->NsSets = malloc(s);
  for(i = 1; i < cpool->NamespaceSetCount; i++)
    parseABC_NS_SET_INFO(cpool->NsSets + i, f);

  cpool->MultinameCount = readEncUInt30(f);
  s = cpool->MultinameCount * sizeof(struct ABC_MULTINAME_INFO);
  cpool->Multinames = malloc(s);
  for(i = 1; i < cpool->MultinameCount; i++)
    parseABC_MULTINAME_INFO(cpool->Multinames + i, f);
}

void parseABC_OPTION_INFO(struct ABC_OPTION_INFO *oinfo, FILE *f)
{
  int i;
  oinfo->OptionCount = readEncUInt30(f);
  oinfo->Option = malloc(sizeof(struct ABC_OPTION_INFO) * oinfo->OptionCount);
  for(i = 0; i < oinfo->OptionCount; i++)
  {
    oinfo->Option[i].Val = readEncUInt30(f);
    oinfo->Option[i].Kind = readUInt8(f);
  }
}

void parseABC_PARAM_INFO(struct ABC_PARAM_INFO *pinfo, U30 count, FILE *f)
{
  int i;
  pinfo->ParamNames = malloc(count * sizeof(U30));
  for(i = 0; i < count; i++)
    pinfo->ParamNames[i] = readEncUInt30(f);
}

void parseABC_METHOD_INFO(struct ABC_METHOD_INFO *method, FILE *f)
{
  int i;

  method->ParamCount = readEncUInt30(f);
  method->ReturnType = readEncUInt30(f);
  method->ParamType = malloc(sizeof(U30) * method->ParamCount);
  for(i = 0; i < method->ParamCount; i++)
    method->ParamType[i] = readEncUInt30(f);
  method->Name = readEncUInt30(f);
  method->Flags = readUInt8(f);
  if(method->Flags & ABC_METHOD_HAS_OPTIONAL)
    parseABC_OPTION_INFO(&method->Options, f);
  if(method->Flags & ABC_METHOD_HAS_PARAM_NAMES)
    parseABC_PARAM_INFO(&method->ParamNames, method->ParamCount, f);
}

void parseABC_METADATA_INFO(struct ABC_METADATA_INFO *meta, FILE *f)
{
  int i;

  meta->Name = readEncUInt30(f);
  meta->ItemCount = readEncUInt30(f);
  meta->Items = malloc(sizeof(struct ABC_ITEM_INFO) * meta->ItemCount);
  for(i = 0; i < meta->ItemCount; i++)
  {
    meta->Items[i].Key = readEncUInt30(f);
    meta->Items[i].Value = readEncUInt30(f);
  }
}

void parseABC_TRAIT_SLOT(struct ABC_TRAIT_SLOT *slot, FILE *f)
{
  slot->SlotId = readEncUInt30(f);
  slot->TypeName = readEncUInt30(f);
  slot->VIndex = readEncUInt30(f);
  if(slot->VIndex)
    slot->VKind = readUInt8(f);
}

void parseABC_TRAIT_CLASS(struct ABC_TRAIT_CLASS *class, FILE *f)
{
  class->SlotId = readEncUInt30(f);
  class->ClassIndex = readEncUInt30(f);
}

void parseABC_TRAIT_FUNCTION(struct ABC_TRAIT_FUNCTION *func, FILE *f)
{
  func->SlotId = readEncUInt30(f);
  func->Function = readEncUInt30(f);
}

void parseABC_TRAIT_METHOD(struct ABC_TRAIT_METHOD *m, FILE *f)
{
  m->DispId = readEncUInt30(f);
  m->Method = readEncUInt30(f);
}

void parseABC_TRAITS_INFO(struct ABC_TRAITS_INFO *trait, FILE *f)
{
  int i;

  trait->Name = readEncUInt30(f);
  trait->Kind = readUInt8(f);
  trait->Attr = (trait->Kind & 0xf0) >> 4;
  switch(trait->Kind & 0x0f) // lower 4-bits for type
  {
    case ABC_CONST_TRAIT_SLOT:
    case ABC_CONST_TRAIT_CONST:
      parseABC_TRAIT_SLOT(&trait->Data.Slot, f);
      break;
    case ABC_CONST_TRAIT_CLASS:
      parseABC_TRAIT_CLASS(&trait->Data.Class, f);
      break;
    case ABC_CONST_TRAIT_FUNCTION:
      parseABC_TRAIT_FUNCTION(&trait->Data.Function, f);
      break;
    case ABC_CONST_TRAIT_METHOD:
    case ABC_CONST_TRAIT_GETTER:
    case ABC_CONST_TRAIT_SETTER:
      parseABC_TRAIT_METHOD(&trait->Data.Method, f);
      break;
    default:
      SWF_error("Unknow trait %x\n", trait->Kind);
  }

  if(trait->Attr & ABC_TRAIT_ATTR_METADATA)
  {
    trait->MetadataCount = readEncUInt30(f);
    trait->Metadata = malloc(trait->MetadataCount * sizeof(U30));
    for(i = 0; i < trait->MetadataCount; i++)
      trait->Metadata[i] = readEncUInt30(f);
  }
}

void parseABC_CLASS_INFO(struct ABC_CLASS_INFO *cinfo, FILE *f)
{
  int i;

  cinfo->CInit = readEncUInt30(f);
  cinfo->TraitCount = readEncUInt30(f);
  cinfo->Traits = malloc(sizeof(struct ABC_TRAITS_INFO) * cinfo->TraitCount);
  for(i = 0; i < cinfo->TraitCount; i++)
    parseABC_TRAITS_INFO(cinfo->Traits + i, f);
}

void parseABC_SCRIPT_INFO(struct ABC_SCRIPT_INFO *sinfo, FILE *f)
{
  int i;

  sinfo->Init = readEncUInt30(f);
  sinfo->TraitCount = readEncUInt30(f);
  sinfo->Traits = malloc(sizeof(struct ABC_TRAITS_INFO) * sinfo->TraitCount);
  for(i = 0; i < sinfo->TraitCount; i++)
    parseABC_TRAITS_INFO(sinfo->Traits + i, f);
}


void parseABC_INSTANCE_INFO(struct ABC_INSTANCE_INFO *inst, FILE *f)
{
  int i;

  inst->Name = readEncUInt30(f);
  inst->SuperName = readEncUInt30(f);
  inst->Flags = readUInt8(f);

  if(inst->Flags & ABC_CLASS_PROTECTED_NS)
    inst->ProtectedNs = readEncUInt30(f);

  inst->InterfaceCount = readEncUInt30(f);
  inst->Interfaces = malloc(inst->InterfaceCount * sizeof(U30));
  for(i = 0; i < inst->InterfaceCount; i++)
    inst->Interfaces[i] = readEncUInt30(f);

  inst->IInit = readEncUInt30(f);

  inst->TraitCount = readEncUInt30(f);
  inst->Traits = malloc(inst->TraitCount * sizeof(struct ABC_TRAITS_INFO));
  for(i = 0; i < inst->TraitCount; i++)
    parseABC_TRAITS_INFO(inst->Traits + i, f);
}

void parseABC_EXCEPTION_INFO(struct ABC_EXCEPTION_INFO *ex, FILE *f)
{
  ex->From = readEncUInt30(f);
  ex->To = readEncUInt30(f);
  ex->Target = readEncUInt30(f);
  ex->ExcType = readEncUInt30(f);
  ex->VarName = readEncUInt30(f);
}

void parseABC_METHOD_BODY_INFO(struct ABC_METHOD_BODY_INFO *minfo, FILE *f)
{
  int i;

  minfo->Method = readEncUInt30(f);
  minfo->MaxStack = readEncUInt30(f);
  minfo->LocalCount = readEncUInt30(f);
  minfo->InitScopeDepth = readEncUInt30(f);
  minfo->MaxScopeDepth = readEncUInt30(f);
  minfo->CodeLength = readEncUInt30(f);
  minfo->Code = (UI8 *)readBytes(f, minfo->CodeLength);
 
  minfo->ExceptionCount = readEncUInt30(f);
  minfo->Exceptions = malloc(minfo->ExceptionCount * sizeof(struct ABC_EXCEPTION_INFO));
  for(i = 0; i < minfo->ExceptionCount; i++)
    parseABC_EXCEPTION_INFO(minfo->Exceptions + i, f);

  minfo->TraitCount = readEncUInt30(f);
  minfo->Traits = malloc(sizeof(struct ABC_TRAITS_INFO) * minfo->TraitCount);
  for(i = 0; i < minfo->TraitCount; i++)
    parseABC_TRAITS_INFO(minfo->Traits + i, f);
}

void parseABC_FILE(struct ABC_FILE *abcFile, FILE *f)
{
  int i;
  size_t size;

  abcFile->Minor = readUInt16(f);
  abcFile->Major = readUInt16(f);
  
  parseABC_CONSTANT_POOL(&abcFile->ConstantPool, f);
   
  abcFile->MethodCount = readEncUInt30(f);
  size = abcFile->MethodCount * sizeof(struct ABC_METHOD_INFO);
  abcFile->Methods = malloc(size);
  for(i = 0; i < abcFile->MethodCount; i++)
    parseABC_METHOD_INFO(abcFile->Methods + i, f);
  
  abcFile->MetadataCount = readEncUInt30(f);
  size = abcFile->MetadataCount * sizeof(struct ABC_METADATA_INFO);
  abcFile->Metadata = malloc(size);
  for(i = 0; i < abcFile->MetadataCount; i++)
    parseABC_METADATA_INFO(abcFile->Metadata + i, f);

  abcFile->ClassCount = readEncUInt30(f);
  size = abcFile->ClassCount * sizeof(struct ABC_INSTANCE_INFO);
  abcFile->Instances = malloc(size);
  size = abcFile->ClassCount * sizeof(struct ABC_CLASS_INFO);
  abcFile->Classes = malloc(size);
  for(i = 0; i < abcFile->ClassCount; i++)
    parseABC_INSTANCE_INFO(abcFile->Instances + i, f);
  for(i = 0; i < abcFile->ClassCount; i++)
    parseABC_CLASS_INFO(abcFile->Classes + i, f);

  abcFile->ScriptCount = readEncUInt30(f);
  size = abcFile->ScriptCount * sizeof(struct ABC_SCRIPT_INFO);
  abcFile->Scripts = malloc(size);
  for(i = 0; i < abcFile->ScriptCount; i++)
    parseABC_SCRIPT_INFO(abcFile->Scripts + i, f);

  abcFile->MethodBodyCount = readEncUInt30(f);
  size = abcFile->MethodBodyCount * sizeof(struct ABC_METHOD_BODY_INFO);
  abcFile->MethodBodies = malloc(size);
  for(i = 0; i < abcFile->MethodBodyCount; i++)
    parseABC_METHOD_BODY_INFO(abcFile->MethodBodies + i, f);
}

SWF_Parserstruct *
parseSWF_DOABC (FILE *f, int length)
{	
  PAR_BEGIN(SWF_DOABC); 
  parserrec->Flags = readUInt32(f);
  parserrec->Name = readString(f);
  parseABC_FILE(&parserrec->AbcFile, f);
  PAR_END;
}

SWF_Parserstruct *
parseSWF_SYMBOLCLASS (FILE *f, int length)
{
  int i, count;
  PAR_BEGIN(SWF_SYMBOLCLASS);
  count = readUInt16(f);
  parserrec->SymbolCount = count;
  parserrec->SymbolList = malloc(count * sizeof(struct SWF_SYMBOLCLASS));
  for(i = 0; i < count; i++)
  {
     parserrec->SymbolList[i].SymbolId = readUInt16(f);
     parserrec->SymbolList[i].SymbolName = readString(f);
  }
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINEBINARYDATA(FILE *f, int length)
{
  PAR_BEGIN(SWF_DEFINEBINARYDATA);
  parserrec->Reserved = readUInt32(f);
  parserrec->Data = (UI8 *)readBytes(f, length - 4);
  parserrec->DataLength = length - 4;
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEFINESCENEANDFRAMEDATA(FILE *f, int length)
{
  int i;
  PAR_BEGIN(SWF_DEFINESCENEANDFRAMEDATA);
  parserrec->SceneCount = readEncUInt32(f);
  parserrec->Scenes = malloc(sizeof(struct SCENE_DATA) * parserrec->SceneCount);
  for(i = 0; i < parserrec->SceneCount; i++)
  {
    parserrec->Scenes[i].Offset = readEncUInt32(f);
    parserrec->Scenes[i].Name = readString(f);
  }
  parserrec->FrameLabelCount = readEncUInt32(f);
  parserrec->Frames = malloc(sizeof(struct FRAME_DATA) * parserrec->FrameLabelCount);
  for(i = 0; i < parserrec->FrameLabelCount; i++)
  {
    parserrec->Frames[i].FrameNum = readEncUInt32(f); 
    parserrec->Frames[i].FrameLabel = readString(f);
  }
  PAR_END;
}

SWF_Parserstruct *
parseSWF_DEBUGID(FILE *f, int length)
{
  PAR_BEGIN(SWF_DEBUGID);
  parserrec->UUID = (UI8 *)readBytes(f, length);
  PAR_END;
}

SWF_Parserstruct *
parseSWF_UNKNOWNBLOCK(FILE *f, int length)
{
  PAR_BEGIN(SWF_UNKNOWNBLOCK);
  parserrec->Data = (UI8 *)readBytes(f, length);
  PAR_END;
}

