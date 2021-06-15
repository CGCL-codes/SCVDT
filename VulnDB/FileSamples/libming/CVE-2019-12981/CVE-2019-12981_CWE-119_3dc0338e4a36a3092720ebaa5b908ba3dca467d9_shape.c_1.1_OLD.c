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

#include <stdlib.h>
#include <stdio.h> 	 
#include <stdarg.h>

#include "shape.h"
#include "character.h"
#include "matrix.h"
#include "fillstyle.h"
#include "linestyle.h"
#include "font.h"
#include "libming.h"

struct stateChangeRecord
{
	int flags;
	int moveToX;
	int moveToY;
	int leftFill;
	int rightFill;
	int line;
	/* newstyle not used.. */
};
typedef struct stateChangeRecord *StateChangeRecord;


struct lineToRecord
{
	int dx;
	int dy;
};
typedef struct lineToRecord *LineToRecord;


struct curveToRecord
{
	int controlx;
	int controly;
	int anchorx;
	int anchory;
};
typedef struct curveToRecord *CurveToRecord;

typedef enum
{
	SHAPERECORD_STATECHANGE,
	SHAPERECORD_LINETO,
	SHAPERECORD_CURVETO
} shapeRecordType;


struct shapeRecord
{
	shapeRecordType type;

	union
	{
		StateChangeRecord stateChange;
		LineToRecord lineTo;
		CurveToRecord curveTo;
	} record;
};
typedef struct shapeRecord ShapeRecord;


struct SWFShape_s
{
	struct SWFCharacter_s character;

	ShapeRecord *records;
	int nRecords;
	SWFOutput out;
	int xpos;	/* cursor for using abs. coords in lineTo, curveTo */
	int ypos;
	SWFLineStyle *lines;
	SWFFillStyle *fills;
	byte nLines;
	byte nFills;
	short lineWidth;
	BOOL isMorph;
	BOOL isEnded;
	int useVersion;
	// SWF_DEFINESHAPE4 extensions
	unsigned char flags;
	SWFRect edgeBounds;
#if TRACK_ALLOCS
	/* memory node for garbage collection */
	mem_node *gcnode;
#endif
};


static void
SWFShape_writeShapeRecord(SWFShape shape, ShapeRecord record, SWFOutput out);


static void
writeSWFShapeBlockToMethod(SWFBlock block, 
                           SWFByteOutputMethod method, void* data)
{
	SWFOutput out = ((SWFShape)block)->out;
	SWFOutput_writeToMethod(out, method, data);
}


static int
completeSWFShapeBlock(SWFBlock block)
{
	SWFShape shape = (SWFShape)block;

	SWFShape_end(shape);
	
	return SWFOutput_getLength(shape->out);
}


void
destroySWFShape(SWFShape shape)
{
	int i;
	if(shape->fills != NULL)
	{
		// Fills have to be destroyed by users. 
		/*
		for ( i=0; i<shape->nFills; ++i )
			destroySWFFillStyle(shape->fills[i]);
		*/
		free(shape->fills);
	}
	if(shape->records != NULL)
	{
		for(i = 0; i < shape->nRecords; i++)
		{
			free(shape->records[i].record.stateChange);
		}
	 	free(shape->records);
	}

	if(shape->edgeBounds != NULL)
		free(shape->edgeBounds);

	for ( i=0; i<shape->nLines; ++i )
		free(shape->lines[i]);

	if ( shape->lines != NULL )
		free(shape->lines);

	destroySWFOutput(shape->out);

#if TRACK_ALLOCS
	ming_gc_remove_node(shape->gcnode);
#endif

	destroySWFCharacter((SWFCharacter) shape);
}

SWFShape 
newSWFGlyphShape()
{
	SWFShape shape = (SWFShape)malloc(sizeof(struct SWFShape_s));

	/* If malloc failed, return NULL to signify this */
	if (NULL == shape)
		return NULL;

	SWFCharacterInit((SWFCharacter)shape);

	BLOCK(shape)->writeBlock = NULL;
	BLOCK(shape)->complete = NULL;
	BLOCK(shape)->dtor = NULL;
	BLOCK(shape)->type = SWF_UNUSEDBLOCK;
	
	shape->out = newSWFOutput();
	CHARACTER(shape)->bounds = newSWFRect(0,0,0,0);
	shape->edgeBounds = newSWFRect(0,0,0,0);

	shape->records = NULL;
	shape->lines = NULL;
	shape->fills = NULL;

	shape->nRecords = 0;
	shape->xpos = 0;
	shape->ypos = 0;
	shape->nLines = 0;
	shape->nFills = 0;
	shape->lineWidth = 0;
	shape->isMorph = FALSE;
	shape->isEnded = FALSE;
	shape->flags = 0;
	shape->useVersion = 0;

	SWFOutput_writeUInt8(shape->out, 0); /* space for nFillBits, nLineBits */

#if TRACK_ALLOCS
	shape->gcnode = ming_gc_add_node(shape, (dtorfunctype) destroySWFShape);
#endif

	return shape;
}

SWFShape
newSWFShape()
{
	SWFShape shape = (SWFShape)malloc(sizeof(struct SWFShape_s));

	/* If malloc failed, return NULL to signify this */
	if (NULL == shape)
		return NULL;

	SWFCharacterInit((SWFCharacter)shape);

	BLOCK(shape)->writeBlock = writeSWFShapeBlockToMethod;
	BLOCK(shape)->complete = completeSWFShapeBlock;
	BLOCK(shape)->dtor = (destroySWFBlockMethod) destroySWFShape;
	BLOCK(shape)->type = SWF_DEFINESHAPE3;
	
	CHARACTERID(shape) = ++SWF_gNumCharacters;

	shape->out = newSWFOutput();
	CHARACTER(shape)->bounds = newSWFRect(0,0,0,0);
	shape->edgeBounds = newSWFRect(0,0,0,0);

	shape->records = NULL;
	shape->lines = NULL;
	shape->fills = NULL;

	shape->nRecords = 0;
	shape->xpos = 0;
	shape->ypos = 0;
	shape->nLines = 0;
	shape->nFills = 0;
	shape->lineWidth = 0;
	shape->isMorph = FALSE;
	shape->isEnded = FALSE;
	shape->flags = 0;
	shape->useVersion = SWF_SHAPE3;

	SWFOutput_writeUInt8(shape->out, 0); /* space for nFillBits, nLineBits */

#if TRACK_ALLOCS
	shape->gcnode = ming_gc_add_node(shape, (dtorfunctype) destroySWFShape);
#endif

	return shape;
}


/*
 * Creates a shape filled with bitmap
 */
SWFShape
newSWFShapeFromBitmap(SWFBitmap bitmap, int flag)
{
	SWFShape shape = newSWFShape();
	SWFFillStyle fill;
	int width, height;

	if ( flag != SWFFILL_TILED_BITMAP &&
	     flag != SWFFILL_CLIPPED_BITMAP &&
	     flag != SWFFILL_NONSMOOTHED_TILED_BITMAP &&
	     flag != SWFFILL_NONSMOOTHED_CLIPPED_BITMAP)
	{
		SWF_error("Invalid bitmap fill flag");
	}

	fill = SWFShape_addBitmapFillStyle(shape, bitmap, flag);

	width = SWFBitmap_getWidth(bitmap);
	height = SWFBitmap_getHeight(bitmap);

	SWFShape_setRightFillStyle(shape, fill);

	// XXX - scale shouldn't be hardcoded! (here, or in newSWFBitmapFillStyle)
	SWFShape_drawScaledLine(shape, width * 20, 0);
	SWFShape_drawScaledLine(shape, 0, height * 20);
	SWFShape_drawScaledLine(shape, -width * 20, 0);
	SWFShape_drawScaledLine(shape, 0, -height * 20);

	return shape;
}

void
SWFOutput_writeGlyphShape(SWFOutput out, SWFShape shape)
{
	unsigned char c;
	int styleDone = 0;
	int i;

	c = 1<<4;
	SWFOutput_writeUInt8(out, c);
	shape->nFills = 1;
	shape->nLines = 0;		
	for ( i=0; i<shape->nRecords; ++i )
	{
		if(!styleDone && shape->records[i].type == SHAPERECORD_STATECHANGE)
		{
			shape->records[i].record.stateChange->flags |= SWF_SHAPE_FILLSTYLE0FLAG;
			shape->records[i].record.stateChange->leftFill = 1;
			styleDone = 1;
		}	
	
		if ( i < shape->nRecords-1 ||
				 shape->records[i].type != SHAPERECORD_STATECHANGE )
		{
			SWFShape_writeShapeRecord(shape, shape->records[i], out);
		}
	}

	SWFOutput_writeBits(out, 0, 6); /* end tag */
	SWFOutput_byteAlign(out);
}

void
SWFShape_end(SWFShape shape)
{
	int i;
	byte* buffer;

	if ( shape->isEnded )
		return;

	shape->isEnded = TRUE;
	
	buffer = SWFOutput_getBuffer(shape->out);
	buffer[0] =
		(SWFOutput_numBits(shape->nFills) << 4) + SWFOutput_numBits(shape->nLines);

	for ( i=0; i<shape->nRecords; ++i )
	{
		if ( i < shape->nRecords-1 ||
				 shape->records[i].type != SHAPERECORD_STATECHANGE )
		{
			SWFShape_writeShapeRecord(shape, shape->records[i], shape->out);
		}

		free(shape->records[i].record.stateChange); /* all in union are pointers */
	}

	SWFOutput_writeBits(shape->out, 0, 6); /* end tag */
	SWFOutput_byteAlign(shape->out);
		
	/* addStyleHeader creates a new output and adds the existing one after
		 itself- so even though it's called afterwards it's written before,
		 as it should be */
	if ( BLOCK(shape)->type > 0 )
	{
		switch (shape->useVersion)
		{
		case SWF_SHAPE1:
			BLOCK(shape)->type = SWF_DEFINESHAPE;
			break;
		case SWF_SHAPE2:
			BLOCK(shape)->type = SWF_DEFINESHAPE2;
			break;
		case SWF_SHAPE4:
			BLOCK(shape)->type = SWF_DEFINESHAPE4;
			break;
		}
		SWFShape_addStyleHeader(shape);
	}
	free(shape->records);
	shape->records = NULL;
	shape->nRecords = 0;
}


SWFOutput
SWFShape_getOutput(SWFShape shape)
{
	return shape->out;
}


void
SWFShape_getFills(SWFShape shape, SWFFillStyle** fills, int* nFills)
{
	*fills = shape->fills;
	*nFills = shape->nFills;
}


void
SWFShape_getLines(SWFShape shape, SWFLineStyle** lines, int* nLines)
{
	*lines = shape->lines;
	*nLines = shape->nLines;
}


void
SWFShape_setMorphFlag(SWFShape shape)
{
	shape->isMorph = TRUE;
}


void
SWFShape_addStyleHeader(SWFShape shape)
{
	SWFOutput out = newSWFOutput();
	SWFOutput_writeUInt16(out, CHARACTERID(shape));
	SWFOutput_writeRect(out, SWFCharacter_getBounds(CHARACTER(shape)));
	if(shape->useVersion == SWF_SHAPE4)
	{
		SWFOutput_writeRect(out, shape->edgeBounds);
		SWFOutput_writeUInt8(out, shape->flags);
	}
	
	SWFOutput_writeFillStyles(out, shape->fills, shape->nFills, 
		BLOCK(shape)->type, shape->edgeBounds);
	SWFOutput_writeLineStyles(out, shape->lines, shape->nLines, 
		BLOCK(shape)->type, shape->edgeBounds);
	
	/* prepend shape->out w/ shape header */
	SWFOutput_setNext(out, shape->out);
	shape->out = out;
}


/*
	ShapeRecords are an intermediate storage so that we don't have to specify
	fill/line types in advance.
*/

#define SHAPERECORD_INCREMENT 32

/* copy shaperecord from other shape */ 
static ShapeRecord addShapeRecord(SWFShape shape, ShapeRecord record, 
                                  int *vx, int *vy, float scale)
{
	if ( shape->nRecords % SHAPERECORD_INCREMENT == 0 )
	{
		shape->records = (ShapeRecord*) realloc(shape->records,
					 sizeof(ShapeRecord) *
					 (shape->nRecords + SHAPERECORD_INCREMENT));
	}

	switch ( record.type )
	{
		case SHAPERECORD_STATECHANGE:
		{
			StateChangeRecord change = (StateChangeRecord)
				calloc(1,sizeof(struct stateChangeRecord));
			*change = *record.record.stateChange;
			shape->records[shape->nRecords].record.stateChange = change;
			change->moveToX += shape->xpos;
			change->moveToY += shape->ypos;
			change->moveToX *= scale;
			change->moveToY *= scale;

			*vx = change->moveToX;
			*vy = change->moveToY;
			break;
		}
		case SHAPERECORD_LINETO:
		{
			LineToRecord lineTo = (LineToRecord)
				calloc(1,sizeof(struct lineToRecord));
			*lineTo = *record.record.lineTo;
			lineTo->dx *= scale;
			lineTo->dy *= scale;
			shape->records[shape->nRecords].record.lineTo = lineTo;

			*vx += lineTo->dx;
			*vy += lineTo->dy;
			SWFRect_includePoint(SWFCharacter_getBounds(CHARACTER(shape)),
				 *vx, *vy, shape->lineWidth);
			SWFRect_includePoint(shape->edgeBounds, *vx, *vy, 0);
			break;
		}
		case SHAPERECORD_CURVETO:
		{
			CurveToRecord curveTo = (CurveToRecord) 
				calloc(1,sizeof(struct curveToRecord));
			*curveTo = *record.record.curveTo;
			curveTo->controlx *= scale;
			curveTo->controly *= scale;
			curveTo->anchorx *= scale;
			curveTo->anchory *= scale;
			shape->records[shape->nRecords].record.curveTo = curveTo;
			
			*vx += curveTo->controlx;
			*vy += curveTo->controly;
			SWFRect_includePoint(SWFCharacter_getBounds(CHARACTER(shape)),
				 *vx, *vy, shape->lineWidth);
			SWFRect_includePoint(shape->edgeBounds, *vx, *vy, 0);
			*vx += curveTo->anchorx;
			*vy += curveTo->anchory;
			SWFRect_includePoint(SWFCharacter_getBounds(CHARACTER(shape)),
				 *vx, *vy, shape->lineWidth);
			SWFRect_includePoint(shape->edgeBounds, *vx, *vy, 0);
			break;
		}
	}
	shape->records[shape->nRecords].type = record.type;
	shape->nRecords++;
	return shape->records[shape->nRecords-1];

}

static ShapeRecord
newShapeRecord(SWFShape shape, shapeRecordType type)
{
	if ( shape->nRecords % SHAPERECORD_INCREMENT == 0 )
	{
		shape->records = (ShapeRecord*) realloc(shape->records,
					 sizeof(ShapeRecord) *
					 (shape->nRecords + SHAPERECORD_INCREMENT));
	}

	switch ( type )
	{
		case SHAPERECORD_STATECHANGE:
		{
			StateChangeRecord change = (StateChangeRecord)calloc(1,sizeof(struct stateChangeRecord));
			shape->records[shape->nRecords].record.stateChange = change;
			break;
		}
		case SHAPERECORD_LINETO:
		{
			LineToRecord lineTo = (LineToRecord) calloc(1,sizeof(struct lineToRecord));
			shape->records[shape->nRecords].record.lineTo = lineTo;
			break;
		}
		case SHAPERECORD_CURVETO:
		{
			CurveToRecord curveTo = (CurveToRecord) calloc(1,sizeof(struct curveToRecord));
			shape->records[shape->nRecords].record.curveTo = curveTo;
			break;
		}
	}

	shape->records[shape->nRecords].type = type;

// this is intentional - at least one popular compiler cannot handle [shape->nRecords++]
	shape->nRecords++;
	return shape->records[shape->nRecords-1];
}


void
SWFShape_writeShapeRecord(SWFShape shape, ShapeRecord record, SWFOutput out)
{
	switch(record.type)
	{
		case SHAPERECORD_STATECHANGE:
		{
			int flags = record.record.stateChange->flags;

			if(flags == 0)
				return;

			SWFOutput_writeBits(out, flags, 6);

			if(flags & SWF_SHAPE_MOVETOFLAG)
			{
				int x = record.record.stateChange->moveToX;
				int y = record.record.stateChange->moveToY;
				int nBits = max(SWFOutput_numSBits(x), SWFOutput_numSBits(y));

				SWF_assert(nBits<32);
				SWFOutput_writeBits(out, nBits, 5);
				SWFOutput_writeSBits(out, x, nBits);
				SWFOutput_writeSBits(out, y, nBits);
			}

			if(flags & SWF_SHAPE_FILLSTYLE0FLAG)
			{
				SWFOutput_writeBits(out, record.record.stateChange->leftFill,
														SWFOutput_numBits(shape->nFills));
			}

			if(flags & SWF_SHAPE_FILLSTYLE1FLAG)
			{
				SWFOutput_writeBits(out, record.record.stateChange->rightFill,
														SWFOutput_numBits(shape->nFills));
			}

			if(flags & SWF_SHAPE_LINESTYLEFLAG)
			{
				SWFOutput_writeBits(out, record.record.stateChange->line,
														SWFOutput_numBits(shape->nLines));
			}

			/* newstyle's never used.	 But this is what it looks like:

			if ( flags & SWF_SHAPE_NEWSTYLEFLAG )
			{
				SWFOutput_writeFillStyles(shape->out, shape->fills, shape->nFills,
				BLOCK(shape)->type);

				SWFOutput_writeLineStyles(shape->out, shape->lines, shape->nLines,
					BLOCK(shape)->type);

				SWFOutput_writeBits(shape->out, SWFOutput_numBits(shape->nFills), 4);
				SWFOutput_writeBits(shape->out, SWFOutput_numBits(shape->nLines), 4);
			}

			*/

			break;
		}

		case SHAPERECORD_LINETO:
		{
			int nBits;
			int dx = record.record.lineTo->dx;
			int dy = record.record.lineTo->dy;

			SWFOutput_writeBits(out, 3, 2); /* straight edge */

			if(dx==0)
			{
				nBits = SWFOutput_numSBits(dy);
				SWF_assert(nBits<18);
				SWFOutput_writeBits(out, nBits-2, 4);
				SWFOutput_writeBits(out, 1, 2); /* vertical line */
				SWFOutput_writeSBits(out, dy, nBits);
			}
			else if(dy==0)
			{
				nBits = SWFOutput_numSBits(dx);
				SWF_assert(nBits<18);
				SWFOutput_writeBits(out, nBits-2, 4);
				SWFOutput_writeBits(out, 0, 2); /* horizontal line */
				SWFOutput_writeSBits(out, dx, nBits);
			}
			else
			{
				nBits = max(SWFOutput_numSBits(dx), SWFOutput_numSBits(dy));
				SWF_assert(nBits<18);
				SWFOutput_writeBits(out, nBits-2, 4);
				SWFOutput_writeBits(out, 1, 1); /* general line */
				SWFOutput_writeSBits(out, dx, nBits);
				SWFOutput_writeSBits(out, dy, nBits);
			}

			break;
		}

		case SHAPERECORD_CURVETO:
		{
			int controlx = record.record.curveTo->controlx;
			int controly = record.record.curveTo->controly;
			int anchorx = record.record.curveTo->anchorx;
			int anchory = record.record.curveTo->anchory;

			int nBits = max(max(SWFOutput_numSBits(controlx),
													SWFOutput_numSBits(controly)),
											max(SWFOutput_numSBits(anchorx),
													SWFOutput_numSBits(anchory)));

			if ( nBits < 2 )
				nBits = 2;

			SWF_assert(nBits < 18);

			SWFOutput_writeBits(out, 2, 2); /* curved edge */
			SWFOutput_writeBits(out, nBits-2, 4);
			SWFOutput_writeSBits(out, controlx, nBits);
			SWFOutput_writeSBits(out, controly, nBits);
			SWFOutput_writeSBits(out, anchorx, nBits);
			SWFOutput_writeSBits(out, anchory, nBits);

			break;
		}

		default:
			SWF_error("Unknown shapeRecordType");
	}
}


/* x,y relative to shape origin */
void
SWFShape_drawScaledLineTo(SWFShape shape, int x, int y)
{
	SWFShape_drawScaledLine(shape, x-shape->xpos, y-shape->ypos);
}


void
SWFShape_drawScaledLine(SWFShape shape, int dx, int dy)
{
	ShapeRecord record;

	if ( shape->isEnded )
		return;

	if ( dx == 0 && dy == 0 )
		return;

	record = newShapeRecord(shape, SHAPERECORD_LINETO);

	SWF_assert(SWFOutput_numSBits(dx) < 18);
	SWF_assert(SWFOutput_numSBits(dy) < 18);

	record.record.lineTo->dx = dx;
	record.record.lineTo->dy = dy;

	shape->xpos += dx;
	shape->ypos += dy;

	SWFRect_includePoint(SWFCharacter_getBounds(CHARACTER(shape)),
											 shape->xpos, shape->ypos, shape->lineWidth);
	SWFRect_includePoint(shape->edgeBounds, shape->xpos, shape->ypos, 0);
}


void
SWFShape_drawScaledCurveTo(SWFShape shape,
													 int controlx, int controly,
													 int anchorx, int anchory)
{
	SWFShape_drawScaledCurve(shape, controlx-shape->xpos, controly-shape->ypos,
													 anchorx-controlx, anchory-controly);
}


void
SWFShape_drawScaledCurve(SWFShape shape,
												 int controldx, int controldy,
												 int anchordx, int anchordy)
{
	ShapeRecord record;

	if ( shape->isEnded )
		return;

	if ( controldx == 0 && controldy == 0 && anchordx == 0 && anchordy == 0 )
		return;
	
	// printf("curve %i,%i, %i, %i\n", controldx, controldy, anchordx,  anchordy);

	record = newShapeRecord(shape, SHAPERECORD_CURVETO);

	record.record.curveTo->controlx = controldx;
	record.record.curveTo->controly = controldy;
	record.record.curveTo->anchorx = anchordx;
	record.record.curveTo->anchory = anchordy;

	if ( SWFOutput_numSBits(controldx) >= 18 ||
			 SWFOutput_numSBits(controldy) >= 18 ||
			 SWFOutput_numSBits(anchordx) >= 18 ||
			 SWFOutput_numSBits(anchordy) >= 18 )
		SWF_error("Curve parameters too large");

	/* including the control point is sloppy, but safe.. */

	shape->xpos += controldx;
	shape->ypos += controldy;

	SWFRect_includePoint(SWFCharacter_getBounds(CHARACTER(shape)),
											 shape->xpos, shape->ypos, shape->lineWidth);
	SWFRect_includePoint(shape->edgeBounds, shape->xpos, shape->ypos, 0);
	shape->xpos += anchordx;
	shape->ypos += anchordy;

	SWFRect_includePoint(SWFCharacter_getBounds(CHARACTER(shape)),
											 shape->xpos, shape->ypos, shape->lineWidth);
	SWFRect_includePoint(shape->edgeBounds, shape->xpos, shape->ypos, 0);
}


#define STYLE_INCREMENT 4

static inline void growLineArray(SWFShape shape)
{
	int size;

	if ( shape->nLines % STYLE_INCREMENT != 0 )
		return;

	size = (shape->nLines+STYLE_INCREMENT) * sizeof(SWFLineStyle);
	shape->lines = (SWFLineStyle*)realloc(shape->lines, size);	
}

static int 
SWFShape_addLineStyle2filled(SWFShape shape, unsigned short width,
                             SWFFillStyle fill,
                             int flags, float miterLimit)
{
	growLineArray(shape);
	SWFShape_useVersion(shape, SWF_SHAPE4);
	SWFFillStyle_addDependency(fill, (SWFCharacter)shape);
	shape->lines[shape->nLines] = newSWFLineStyle2_filled(width, fill, flags, miterLimit);
	return ++shape->nLines;
}

static int
SWFShape_addLineStyle2(SWFShape shape, unsigned short width,
                      byte r, byte g, byte b, byte a,
                      int flags, float miterLimit)
{
	growLineArray(shape);
	SWFShape_useVersion(shape, SWF_SHAPE4);
	shape->lines[shape->nLines] = newSWFLineStyle2(width, r, g, b, a, flags, miterLimit);
	return ++shape->nLines;
}

static int
SWFShape_addLineStyle(SWFShape shape, unsigned short width,
                      byte r, byte g, byte b, byte a)
{
	growLineArray(shape);
	shape->lines[shape->nLines] = newSWFLineStyle(width, r, g, b, a);
	return ++shape->nLines;
}


/* if the current shape record isn't a style change record, add one */
static ShapeRecord
addStyleRecord(SWFShape shape)
{
	if ( shape->nRecords > 0 &&
			 shape->records[shape->nRecords-1].type == SHAPERECORD_STATECHANGE )
	{
		return shape->records[shape->nRecords-1];
	}
	else
		return newShapeRecord(shape, SHAPERECORD_STATECHANGE);
}


void
SWFShape_hideLine(SWFShape shape)
{
	ShapeRecord record;

	if ( shape->isEnded )
		return;

	if ( shape->isMorph )
		return;

	record = addStyleRecord(shape);

	record.record.stateChange->line = 0;
	record.record.stateChange->flags |= SWF_SHAPE_LINESTYLEFLAG;
}

static void finishSetLine(SWFShape shape, int line, unsigned short width)
{
	ShapeRecord record;
	
	if ( width == 0 )
		shape->lineWidth = 0;
	else
		shape->lineWidth = (SWFLineStyle_getWidth(shape->lines[line-1]) + 1) / 2;
	
	if ( shape->isMorph )
		return;

	record = addStyleRecord(shape);

	record.record.stateChange->line = line;
	record.record.stateChange->flags |= SWF_SHAPE_LINESTYLEFLAG;
}

/*
 * set filled Linestyle2 introduce with SWF 8.
 * 
 * set line width in TWIPS
 *
 * WARNING: this is an internal interface
 * external use is deprecated! use setLine2 instead
 *
 * Instead of providing a fill color, a FillStyle can be applied
 * to a line.
 * 
 * Linestyle2 also extends Linestyle1 with some extra flags:
 *
 * Line cap style: select one of the following flags (default is round cap style)
 * SWF_LINESTYLE_CAP_ROUND 
 * SWF_LINESTYLE_CAP_NONE
 * SWF_LINESTYLE_CAP_SQUARE 
 *
 * Line join style: select one of the following flags (default is round join style)
 * SWF_LINESTYLE_JOIN_ROUND
 * SWF_LINESTYLE_JOIN_BEVEL 
 * SWF_LINESTYLE_JOIN_MITER  
 *
 * Scaling flags: disable horizontal / vertical scaling
 * SWF_LINESTYLE_FLAG_NOHSCALE
 * SWF_LINESTYLE_FLAG_NOVSCALE 
 *
 * Enable pixel hinting to correct blurry vertical / horizontal lines
 * -> all anchors will be aligned to full pixels
 * SWF_LINESTYLE_FLAG_HINTING  
 *
 * Disable stroke closure: if no-close flag is set caps will be applied 
 * instead of joins
 * SWF_LINESTYLE_FLAG_NOCLOSE
 *
 * End-cap style: default round
 * SWF_LINESTYLE_FLAG_ENDCAP_ROUND
 * SWF_LINESTYLE_FLAG_ENDCAP_NONE
 * SWF_LINESTYLE_FLAG_ENDCAP_SQUARE
 *
 * If join style is SWF_LINESTYLE_JOIN_MITER a miter limit factor 
 * must be set. Miter max length is then calculated as:
 * max miter len = miter limit * width.
 * If join style is not miter, this value will be ignored.
 */
void 
SWFShape_setLineStyle2filled_internal(SWFShape shape, unsigned short width,
                       SWFFillStyle fill,
                       int flags, float miterLimit)
{
	int line;

	if ( shape->isEnded )
		return;

	for ( line=0; line<shape->nLines; ++line )
	{
		if ( SWFLineStyle_equals2filled(shape->lines[line], width, fill, flags) )
			break;
	}

	if ( line == shape->nLines )
		line = SWFShape_addLineStyle2filled(shape, width, fill, flags, miterLimit);
	else
		++line;

	finishSetLine(shape, line, width);
}


/*
 * set Linestyle2 introduce with SWF 8.
 *
 * set line width in TWIPS
 * WARNING: this is an internal interface
 * external use is deprecated! use setLine2 instead !
 * set color {r, g, b, a}
 *
 * Linestyle2 extends Linestyle1 with some extra flags:
 *
 * Line cap style: select one of the following flags (default is round cap style)
 * SWF_LINESTYLE_CAP_ROUND 
 * SWF_LINESTYLE_CAP_NONE
 * SWF_LINESTYLE_CAP_SQUARE 
 *
 * Line join style: select one of the following flags (default is round join style)
 * SWF_LINESTYLE_JOIN_ROUND
 * SWF_LINESTYLE_JOIN_BEVEL 
 * SWF_LINESTYLE_JOIN_MITER  
 *
 * Scaling flags: disable horizontal / vertical scaling
 * SWF_LINESTYLE_FLAG_NOHSCALE
 * SWF_LINESTYLE_FLAG_NOVSCALE 
 *
 * Enable pixel hinting to correct blurry vertical / horizontal lines
 * -> all anchors will be aligned to full pixels
 * SWF_LINESTYLE_FLAG_HINTING  
 *
 * Disable stroke closure: if no-close flag is set caps will be applied 
 * instead of joins
 * SWF_LINESTYLE_FLAG_NOCLOSE
 *
 * End-cap style: default round
 * SWF_LINESTYLE_FLAG_ENDCAP_ROUND
 * SWF_LINESTYLE_FLAG_ENDCAP_NONE
 * SWF_LINESTYLE_FLAG_ENDCAP_SQUARE
 *
 * If join style is SWF_LINESTYLE_JOIN_MITER a miter limit factor 
 * must be set. Miter max length is then calculated as:
 * max miter len = miter limit * width.
 * If join style is not miter, this value will be ignored.
 */
void 
SWFShape_setLineStyle2_internal(SWFShape shape, unsigned short width,
                       byte r, byte g, byte b, byte a,
                       int flags, float miterLimit)
{
	int line;

	if ( shape->isEnded )
		return;

	for ( line=0; line<shape->nLines; ++line )
	{
		if ( SWFLineStyle_equals(shape->lines[line], width, r, g, b, a, flags) )
			break;
	}

	if ( line == shape->nLines )
		line = SWFShape_addLineStyle2(shape, width, r, g, b, a, flags, miterLimit);
	else
		++line;

	finishSetLine(shape, line, width);
}


/*
 * set line width and line color
 *
 * set line width in TWIPS
 * set line color as {r, g, b, a}
 *
 * WARNING: this is an internal interface.
 * external use is deprecated! use setLine instead ! 
 */
void
SWFShape_setLineStyle_internal(SWFShape shape, unsigned short width,
                      byte r, byte g, byte b, byte a)
{
	int line;
		
	if ( shape->isEnded )
		return;
	
	for ( line=0; line<shape->nLines; ++line )
	{
		if ( SWFLineStyle_equals(shape->lines[line], width, r, g, b, a, 0) )
			break;
	}

	if ( line == shape->nLines )
		line = SWFShape_addLineStyle(shape, width, r, g, b, a);
	else
		++line;
	
	finishSetLine(shape, line, width);
}


/* fill 0 is no fill, so set idx to one more than the shape's fill index */
static int getFillIdx(SWFShape shape, SWFFillStyle fill)
{
	int i;

	for ( i=0; i<shape->nFills; ++i )
	{
		if ( SWFFillStyle_equals(fill, shape->fills[i]) )
			return (i+1);
	}
	return 0; // no fill
}

static int addFillStyle(SWFShape shape, SWFFillStyle fill)
{
	int i;
	
	for ( i=0; i<shape->nFills; ++i )
	{
		if ( SWFFillStyle_equals(fill, shape->fills[i]) )
			return i;
	}

	if ( shape->isEnded )
		return -1;

	if ( shape->nFills%STYLE_INCREMENT == 0 )
	{
		int size = (shape->nFills+STYLE_INCREMENT) * sizeof(SWFFillStyle);
		shape->fills = (SWFFillStyle*)realloc(shape->fills, size);
	}

	shape->fills[shape->nFills] = fill;
	++shape->nFills;
	return shape->nFills;
}


SWFFillStyle
SWFShape_addSolidFillStyle(SWFShape shape, byte r, byte g, byte b, byte a)
{
	int  ret;

	SWFFillStyle fill = newSWFSolidFillStyle(r, g, b, a);
	
	ret = addFillStyle(shape, fill);
	if(ret < 0) /* error */
	{
		destroySWFFillStyle(fill);
		return NULL;
	}
	else if(ret == shape->nFills)  /* new fill */
	{
		return fill;
	}
	else /* fill is known */ 
	{
		destroySWFFillStyle(fill);
		return shape->fills[ret];
	}
}


SWFFillStyle
SWFShape_addGradientFillStyle(SWFShape shape, SWFGradient gradient, byte flags)
{
	SWFFillStyle fill = newSWFGradientFillStyle(gradient, flags);
	if(addFillStyle(shape, fill) < 0)
	{
		destroySWFFillStyle(fill);
		return NULL;
	}
	return fill;		
}


SWFFillStyle
SWFShape_addBitmapFillStyle(SWFShape shape, SWFBitmap bitmap, byte flags)
{
	SWFFillStyle fill;

	if ( bitmap )
	{
		SWFCharacter_addDependency((SWFCharacter)shape,
		                           (SWFCharacter)bitmap);
	}

	fill = newSWFBitmapFillStyle(bitmap, flags);
	if(addFillStyle(shape, fill) < 0)
	{
		destroySWFFillStyle(fill);
		return NULL;
	}
	return fill;
}


void
SWFShape_setLeftFillStyle(SWFShape shape, SWFFillStyle fill)
{
	ShapeRecord record;
	int idx;

	if ( shape->isEnded || shape->isMorph )
		return;
	
	if(fill == NOFILL)
	{
		record = addStyleRecord(shape);
		record.record.stateChange->leftFill = 0;
		record.record.stateChange->flags |= SWF_SHAPE_FILLSTYLE0FLAG;
		return;
	}

	idx = getFillIdx(shape, fill);
	if(idx == 0) // fill not present in array
	{
		SWFFillStyle_addDependency(fill, (SWFCharacter)shape);
		if(addFillStyle(shape, fill) < 0)
			return;		
		idx = getFillIdx(shape, fill);
	}
				
	record = addStyleRecord(shape);
	record.record.stateChange->leftFill = idx;
	record.record.stateChange->flags |= SWF_SHAPE_FILLSTYLE0FLAG;
}


void
SWFShape_setRightFillStyle(SWFShape shape, SWFFillStyle fill)
{
	ShapeRecord record;
	int idx;

	if ( shape->isEnded || shape->isMorph )
		return;
	
	if(fill == NOFILL)
	{
		record = addStyleRecord(shape);
		record.record.stateChange->rightFill = 0;
		record.record.stateChange->flags |= SWF_SHAPE_FILLSTYLE1FLAG;
		return;
	}

	idx = getFillIdx(shape, fill);
	if(idx == 0) // fill not present in array
	{
		SWFFillStyle_addDependency(fill, (SWFCharacter)shape);
		if(addFillStyle(shape, fill) < 0)
			return;		
		idx = getFillIdx(shape, fill);
	}
	else if (idx >= 255 && shape->useVersion == SWF_SHAPE1)
	{
		SWF_error("Too many fills for SWFShape V1.\n" 
			  "Use a higher SWFShape version\n");
	}
				
	record = addStyleRecord(shape);
	record.record.stateChange->rightFill = idx;
	record.record.stateChange->flags |= SWF_SHAPE_FILLSTYLE1FLAG;
}

/* move pen relative to shape origin */
void
SWFShape_moveScaledPenTo(SWFShape shape, int x, int y)
{
	ShapeRecord record;
	if ( shape->isEnded )
		return;

	record = addStyleRecord(shape);

	record.record.stateChange->moveToX = shape->xpos = x;
	record.record.stateChange->moveToY = shape->ypos = y;

	record.record.stateChange->flags |= SWF_SHAPE_MOVETOFLAG;

	if ( shape->nRecords == 0 ||
			 (shape->nRecords == 1 &&
				shape->records[0].type == SHAPERECORD_STATECHANGE) )
	{
		SWFRect_setBounds(SWFCharacter_getBounds(CHARACTER(shape)), x, x, y, y);
		SWFRect_setBounds(shape->edgeBounds, x, x, y, y);
	}
}


void
SWFShape_moveScaledPen(SWFShape shape, int x, int y)
{
	SWFShape_moveScaledPenTo(shape, shape->xpos+x, shape->ypos+y);
}


int
SWFShape_getScaledPenX(SWFShape shape)
{
	return shape->xpos;
}


int
SWFShape_getScaledPenY(SWFShape shape)
{
	return shape->ypos;
}

void
SWFShape_drawScaledGlyph(SWFShape shape,
                         SWFFont font, unsigned short c, int size)
{
	SWFShape glyph;
	int i, vx, vy;
	if(font == NULL)
		return;
	
	glyph = SWFFont_getGlyph(font, c);
	if(glyph == NULL)
	{
		SWF_warn("SWFShape_drawScaledGlyph: no glyph for code %i found \n", c);
		return;
	}

	vx = shape->xpos;
	vy = shape->ypos;
	for(i = 0; i < glyph->nRecords; i++)
		addShapeRecord(shape, glyph->records[i], &vx, &vy, size/1024.0);
}

/*
 * set shape version manualy
 * This function allows to set the shapes version information. The
 * version is only a hint. if necessary the version is upgraded. 
 * valid values: SWF_SHAPE3 and SWF_SHAPE4 
 * 3 is default
 * 4 if linestyle2 is used
 */
void SWFShape_useVersion(SWFShape shape, int version)
{
	if(shape->useVersion >= version)
		return;
	if(version > SWF_SHAPE4)
		return;
	shape->useVersion = version;
}

/*
 * get shape version
 * possible values SWF_SHAPE3 and SWF_SHAPE4 
 */
int SWFShape_getVersion(SWFShape shape)
{
	return shape->useVersion;
}

/* 
 * set render hinting flags
 * possible values:
 * SWF_SHAPE_USESCALINGSTROKES 	SWF_SHAPE_USENONSCALINGSTROKES	
 */
void SWFShape_setRenderHintingFlags(SWFShape shape, int flags)
{
	flags &= (SWF_SHAPE_USESCALINGSTROKES | SWF_SHAPE_USENONSCALINGSTROKES);
	shape->flags = flags;
	SWFShape_useVersion(shape, SWF_SHAPE4);
}

SWFRect SWFShape_getEdgeBounds(SWFShape shape)
{
	if(shape->useVersion == SWF_SHAPE4)
		return shape->edgeBounds;
	else
		return NULL;
}

int SWFShape_getFlags(SWFShape shape)
{
	if(shape->useVersion == SWF_SHAPE4)
		return shape->flags;
	else
		return 0;
}

struct out 	 
{       char *buf, *ptr; 	 
	int len; 	 
}; 	 
	  	 
static void oprintf(struct out *op, const char *fmt, ...) 	 
{
	va_list ap; 	 
	char buf[256]; 	 
	int d, l; 	 
	  	 
	va_start(ap, fmt); 	 
	l = vsprintf(buf, fmt, ap); 	 
	while((d = op->ptr - op->buf) + l >= op->len-1) 	 
	{
		op->buf = (char *) realloc(op->buf, op->len += 100); 	 
		op->ptr = op->buf + d; 	 
	} 	 
	for(d = 0 ; d < l ; d++) 	 
		*op->ptr++ = buf[d]; 	 
}

char * SWFShape_dumpOutline(SWFShape s) 	 
{ 	 
	struct out o; 	 
	int i;
	int x = 0, y = 0;
 
	o.len = 0; 	 
	o.ptr = o.buf = (char *)malloc(1); 	 
	*o.ptr = 0; 	 
	  	 
	for (i = 0; i < s->nRecords; i++) 	 
	{
		ShapeRecord *record = s->records + i;
		switch(record->type)
		{
		case SHAPERECORD_STATECHANGE:
		{
			if(!record->record.stateChange->flags & SWF_SHAPE_MOVETOFLAG)
				continue;
			x = record->record.stateChange->moveToX;
			y = record->record.stateChange->moveToY;
			oprintf(&o, "moveto %d,%d\n", x, y);
			break;
		}
	  	case SHAPERECORD_LINETO:
		{
			x += record->record.lineTo->dx;
			y += record->record.lineTo->dy;
			oprintf(&o, "lineto %d,%d\n", x, y);
			break; 	 
		} 	 
		case SHAPERECORD_CURVETO: 	 
		{ 	 
			int controlX = record->record.curveTo->controlx;
			int controlY = record->record.curveTo->controly;
			int anchorX = record->record.curveTo->anchorx;
			int anchorY = record->record.curveTo->anchory;

			oprintf(&o, "curveto %d,%d %d,%d\n", 	 
				x+controlX, y+controlY, 	 
				x+controlX+anchorX, y+controlY+anchorY); 	 
	  	 
				x += controlX + anchorX; 	 
				y += controlY + anchorY;
			break; 
		}
		default: break;
		}
	} 	 
	  	 
	*o.ptr = 0; 	 
	return o.buf; 	 
}


/*
 * Local variables:
 * tab-width: 2
 * c-basic-offset: 2
 * End:
 */
