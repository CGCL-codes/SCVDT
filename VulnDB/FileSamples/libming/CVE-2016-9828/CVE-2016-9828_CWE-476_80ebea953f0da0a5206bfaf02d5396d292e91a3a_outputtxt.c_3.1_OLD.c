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

#include "blocks/blocktypes.h"
#include "action.h"
#include "parser.h"
#include "read.h"
#include "decompile.h"
#include "swfoutput.h"
#include "abctypes.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

extern const char *blockName (SWFBlocktype header);

extern int verbose;

extern struct Movie m;
/*
 * This file contains output functions that can display the different SWF block
 * types in a human readable format.
 */

#define OUT_BEGIN(block) \
	struct block *sblock = (struct block *)pblock;

static struct SWFBlockOutput outputs[] = {
  {SWF_CHARACTERSET, outputSWF_CHARACTERSET},
  {SWF_DEFINEBITS, outputSWF_DEFINEBITS},
  {SWF_DEFINEBITSJPEG2, outputSWF_DEFINEBITSJPEG2},
  {SWF_DEFINEBITSJPEG3, outputSWF_DEFINEBITSJPEG3},
  {SWF_DEFINEBITSPTR, outputSWF_DEFINEBITSPTR},
  {SWF_DEFINEBUTTON, outputSWF_DEFINEBUTTON},
  {SWF_DEFINEBUTTON2, outputSWF_DEFINEBUTTON2},
  {SWF_DEFINEBUTTONCXFORM, outputSWF_DEFINEBUTTONCXFORM},
  {SWF_DEFINEBUTTONSOUND, outputSWF_DEFINEBUTTONSOUND},
  {SWF_DEFINECOMMANDOBJ, outputSWF_DEFINECOMMANDOBJ},
  {SWF_DEFINEEDITTEXT, outputSWF_DEFINEEDITTEXT},
  {SWF_DEFINEFONT, outputSWF_DEFINEFONT},
  {SWF_DEFINEFONT2, outputSWF_DEFINEFONT2},
  {SWF_DEFINEFONT3, outputSWF_DEFINEFONT3},
  {SWF_DEFINEFONTINFO, outputSWF_DEFINEFONTINFO},
  {SWF_DEFINEFONTINFO2, outputSWF_DEFINEFONTINFO2},
  {SWF_CSMTEXTSETTINGS, outputSWF_CSMTEXTSETTINGS},
  {SWF_DEFINEFONTNAME, outputSWF_DEFINEFONTNAME},
  {SWF_DEFINEFONTALIGNZONES, outputSWF_DEFINEFONTALIGNZONES},
  {SWF_DEFINELOSSLESS, outputSWF_DEFINELOSSLESS},
  {SWF_DEFINELOSSLESS2, outputSWF_DEFINELOSSLESS2},
  {SWF_DEFINEMORPHSHAPE, outputSWF_DEFINEMORPHSHAPE},
  {SWF_DEFINEMORPHSHAPE2, outputSWF_DEFINEMORPHSHAPE2},
  {SWF_DEFINESHAPE, outputSWF_DEFINESHAPE},
  {SWF_DEFINESHAPE2, outputSWF_DEFINESHAPE2},
  {SWF_DEFINESHAPE3, outputSWF_DEFINESHAPE3},
  {SWF_DEFINESHAPE4, outputSWF_DEFINESHAPE4},
  {SWF_DEFINESOUND, outputSWF_DEFINESOUND},
  {SWF_DEFINESPRITE, outputSWF_DEFINESPRITE},
  {SWF_DEFINETEXT, outputSWF_DEFINETEXT},
  {SWF_DEFINETEXT2, outputSWF_DEFINETEXT2},
  {SWF_DEFINETEXTFORMAT, outputSWF_DEFINETEXTFORMAT},
  {SWF_DEFINEVIDEO, outputSWF_DEFINEVIDEO},
  {SWF_DEFINEVIDEOSTREAM, outputSWF_DEFINEVIDEOSTREAM},
  {SWF_DOACTION, outputSWF_DOACTION},
  {SWF_ENABLEDEBUGGER, outputSWF_ENABLEDEBUGGER},
  {SWF_ENABLEDEBUGGER2, outputSWF_ENABLEDEBUGGER2},
  {SWF_END, outputSWF_END},
  {SWF_EXPORTASSETS, outputSWF_EXPORTASSETS},
  {SWF_FONTREF, outputSWF_FONTREF},
  {SWF_FRAMELABEL, outputSWF_FRAMELABEL},
  {SWF_FRAMETAG, outputSWF_FRAMETAG},
  {SWF_FREEALL, outputSWF_FREEALL},
  {SWF_FREECHARACTER, outputSWF_FREECHARACTER},
  {SWF_GENCOMMAND, outputSWF_GENCOMMAND},
  {SWF_IMPORTASSETS, outputSWF_IMPORTASSETS},
  {SWF_IMPORTASSETS2, outputSWF_IMPORTASSETS2},
  {SWF_JPEGTABLES, outputSWF_JPEGTABLES},
  {SWF_NAMECHARACTER, outputSWF_NAMECHARACTER},
  {SWF_PATHSAREPOSTSCRIPT, outputSWF_PATHSAREPOSTSCRIPT},
  {SWF_PLACEOBJECT, outputSWF_PLACEOBJECT},
  {SWF_PLACEOBJECT2, outputSWF_PLACEOBJECT2},
  {SWF_PLACEOBJECT3, outputSWF_PLACEOBJECT3},
  {SWF_PREBUILT, outputSWF_PREBUILT},
  {SWF_PREBUILTCLIP, outputSWF_PREBUILTCLIP},
  {SWF_PROTECT, outputSWF_PROTECT},
  {SWF_REMOVEOBJECT, outputSWF_REMOVEOBJECT},
  {SWF_REMOVEOBJECT2, outputSWF_REMOVEOBJECT2},
  {SWF_SERIALNUMBER, outputSWF_SERIALNUMBER},
  {SWF_SETBACKGROUNDCOLOR, outputSWF_SETBACKGROUNDCOLOR},
  {SWF_SHOWFRAME, outputSWF_SHOWFRAME},
  {SWF_SOUNDSTREAMBLOCK, outputSWF_SOUNDSTREAMBLOCK},
  {SWF_SOUNDSTREAMHEAD, outputSWF_SOUNDSTREAMHEAD},
  {SWF_SOUNDSTREAMHEAD2, outputSWF_SOUNDSTREAMHEAD2},
  {SWF_STARTSOUND, outputSWF_STARTSOUND},
  {SWF_STARTSOUND2, outputSWF_STARTSOUND2},
  {SWF_SYNCFRAME, outputSWF_SYNCFRAME},
  {SWF_INITACTION, outputSWF_INITACTION},
  {SWF_VIDEOFRAME, outputSWF_VIDEOFRAME},
  {SWF_REFLEX, outputSWF_REFLEX},
  {SWF_FILEATTRIBUTES, outputSWF_FILEATTRIBUTES},
  {SWF_METADATA, outputSWF_METADATA},
  {SWF_SCRIPTLIMITS, outputSWF_SCRIPTLIMITS},
  {SWF_DEFINESCALINGGRID, outputSWF_DEFINESCALINGGRID},
  {SWF_SETTABINDEX, outputSWF_SETTABINDEX},
  {SWF_DOABC, outputSWF_DOABC},
  {SWF_SYMBOLCLASS, outputSWF_SYMBOLCLASS},
  {SWF_DEFINESCENEANDFRAMEDATA, outputSWF_DEFINESCENEANDFRAMEDATA},
  {SWF_DEBUGID, outputSWF_DEBUGID},
};

static int numOutputs = sizeof (outputs) / sizeof (struct SWFBlockOutput);

/* Indented output function */

static unsigned INDENT=0;

static void
_iprintf(const char* fmt, ...)
{
	va_list ap;
	unsigned ii=INDENT;

	/* do intenting */
	while(ii--) printf("  ");

	va_start (ap, fmt);
	vprintf(fmt, ap);
	return;
}

/* Output basic Flash Types */

void
outputSWF_RGBA (SWF_RGBA * rgb, char *pname)
{
  _iprintf (" RGBA: (");
  _iprintf ("%2x,", rgb->red);
  _iprintf ("%2x,", rgb->green);
  _iprintf ("%2x,", rgb->blue);
  _iprintf ("%2x)\n", rgb->alpha);
}

void
outputSWF_RECT (SWF_RECT * rect)
{
  _iprintf (" RECT: ");
  _iprintf (" (%ld,", rect->Xmin);
  _iprintf ("%ld)x", rect->Ymin);
  _iprintf ("(%ld,", rect->Xmax);
  _iprintf ("%ld)", rect->Ymax);
  _iprintf (":%d\n", rect->Nbits);
}

void
outputSWF_MATRIX (SWF_MATRIX * matrix, char *name)
{
  _iprintf ("  Matrix:\n");
  if (matrix->HasScale)
    {
      _iprintf ("   ScaleX %f ", matrix->ScaleX);
      _iprintf ("ScaleY %f\n", matrix->ScaleY);
    }
  if (matrix->HasRotate)
    {
      _iprintf ("   RotateSkew0 %f ", matrix->RotateSkew0);
      _iprintf ("RotateSkew1 %f\n", matrix->RotateSkew1);
    }
  _iprintf ("   TranslateX %6ld ", matrix->TranslateX);
  _iprintf ("TranslateY %6ld\n", matrix->TranslateY);
}

void
outputSWF_CXFORM(SWF_CXFORM * cxform){
	_iprintf("  ColorTransform:\n");
	if (cxform->HasMultTerms){
		_iprintf("   Mult:");
		_iprintf("%ld,", cxform->RedMultTerm);
		_iprintf("%ld,", cxform->GreenMultTerm);
		_iprintf("%ld,", cxform->BlueMultTerm);
		/*
		if (cxform->hasAlpha){
			_iprintf("%ld", cxform->AlphaMultTerm);	
		}
		*/
		_iprintf("\n");
	}
	
	if (cxform->HasAddTerms){
		_iprintf("   Add:");	
		_iprintf("%ld,", cxform->RedAddTerm);
		_iprintf("%ld,", cxform->GreenAddTerm);
		_iprintf("%ld,", cxform->BlueAddTerm);
		/*
		if (cxform->hasAlpha){
			_iprintf("%ld", cxform->AlphaAddTerm);	
		}
		*/
		_iprintf("\n");
	}
}

/* alpha could be handled in SWF_CXFORM / outputSWF_CXFORM too
*  or is there a reason to make 
* 2 parsefunctions /
* 2 cxform structures
* 2 outputfunctions
* for that?
*/
void
outputSWF_CXFORMWITHALPHA(SWF_CXFORMWITHALPHA * cxform, char *name){
	_iprintf("  ColorTransform:\n");
	if (cxform->HasMultTerms){
		_iprintf("   Mult:");
		_iprintf("%ld,", cxform->RedMultTerm);
		_iprintf("%ld,", cxform->GreenMultTerm);
		_iprintf("%ld,", cxform->BlueMultTerm);
		_iprintf("%ld",  cxform->AlphaMultTerm);
		_iprintf("\n");
	}
	if (cxform->HasAddTerms){
		_iprintf("   Add:");
		_iprintf("%ld,", cxform->RedAddTerm);
		_iprintf("%ld,", cxform->GreenAddTerm);
		_iprintf("%ld,", cxform->BlueAddTerm);
		_iprintf("%ld",  cxform->AlphaAddTerm);
		_iprintf("\n");
	}	
}

void 
outputSWF_FILTER(SWF_FILTER *filter);

void
outputSWF_BUTTONRECORD (SWF_BUTTONRECORD *brec)
{
  _iprintf (" BUTTONRECORD: ");
  _iprintf ("  ButtonHasBlendMode %d ", brec->ButtonHasBlendMode);
  _iprintf ("  ButtonHasFilterList %d ", brec->ButtonHasFilterList);
  _iprintf ("  ButtonStateHitTest: %d ", brec->ButtonStateHitTest);
  _iprintf ("  ButtonStateDown: %d ", brec->ButtonStateDown);
  _iprintf ("  ButtonStateOver: %d ", brec->ButtonStateOver);
  _iprintf ("  ButtonStateUp: %d\n", brec->ButtonStateUp);
  _iprintf ("  CharacterID: %d\n", brec->CharacterId);
  _iprintf ("  PlaceDepth: %d\n", brec->PlaceDepth);

	outputSWF_MATRIX(&brec->PlaceMatrix,"");
	outputSWF_CXFORMWITHALPHA(&brec->ColorTransform,"");
  if( brec->ButtonHasBlendMode )
	  _iprintf("  BlendMode %d\n", brec->BlendMode );
  if( brec->ButtonHasFilterList )
  {
	  int i;
	  SWF_FILTERLIST *filterList = &brec->FilterList;
	  
	  _iprintf("  NumberOfFilters %d\n", filterList->NumberOfFilters);
	  
	  for(i = 0; i < filterList->NumberOfFilters; i++)
	    outputSWF_FILTER(filterList->Filter + i);
  }
}

void
outputSWF_BUTTONCONDACTION (SWF_BUTTONCONDACTION *bcarec)
{
#ifdef NODECOMPILE
  int i;
#endif
#if !defined(ACTIONONLY)
  _iprintf (" BUTTONCONDACTION: ");
  _iprintf ("  CondActionSize: %d\n", bcarec->CondActionSize);
  _iprintf ("  CondIdleToOverDown: %d ", bcarec->CondIdleToOverDown);
  _iprintf ("  CondOutDownToIdle: %d ", bcarec->CondOutDownToIdle);
  _iprintf ("  CondOutDownToOverDown: %d ", bcarec->CondOutDownToOverDown);
  _iprintf ("  CondOverDownToOutDown: %d ", bcarec->CondOverDownToOutDown);
  _iprintf ("  CondOverDownToOverUp: %d ", bcarec->CondOverDownToOverUp);
  _iprintf ("  CondOverUpToOverDown: %d ", bcarec->CondOverUpToOverDown);
  _iprintf ("  CondOverUpToIdle: %d ", bcarec->CondOverUpToIdle);
  _iprintf ("  CondIdleToOverUp: %d ", bcarec->CondIdleToOverUp);
  _iprintf ("  CondKeyPress: %d ", bcarec->CondKeyPress);
  _iprintf ("  CondOverDownToIdle: %d ", bcarec->CondOverDownToIdle);
  _iprintf ("\n");
#endif
#ifdef NODECOMPILE
  _iprintf(" %d Actions\n", bcarec->numActions);
  for(i=0;i<bcarec->numActions;i++)
  outputSWF_ACTION(i,&(bcarec->Actions[i]));
#else
  _iprintf (" %s\n", decompile5Action(bcarec->numActions,bcarec->Actions,0));
#endif
}

void
outputSWF_CLIPEVENTFLAGS (SWF_CLIPEVENTFLAGS * clipevflags )
{
  if ( clipevflags->ClipEventKeyUp ) printf (" ClipEventKeyUp");
  if ( clipevflags->ClipEventKeyDown ) printf (" ClipEventKeyDown");
  if ( clipevflags->ClipEventMouseUp ) printf (" ClipEventMouseUp");
  if ( clipevflags->ClipEventMouseDown ) printf (" ClipEventMouseDown");
  if ( clipevflags->ClipEventMouseMove ) printf (" ClipEventMouseMove");
  if ( clipevflags->ClipEventUnload ) printf (" ClipEventUnload");
  if ( clipevflags->ClipEventEnterFrame ) printf (" ClipEventEnterFrame");
  if ( clipevflags->ClipEventLoad ) printf (" ClipEventLoad");
  if ( clipevflags->ClipEventDragOver ) printf (" ClipEventDragOver");
  if ( clipevflags->ClipEventRollOut ) printf (" ClipEventRollOut");
  if ( clipevflags->ClipEventRollOver ) printf (" ClipEventRollOver");
  if ( clipevflags->ClipEventReleaseOutside ) printf (" ClipEventReleaseOutside");
  if ( clipevflags->ClipEventRelease ) _iprintf (" ClipEventRelease");
  if ( clipevflags->ClipEventPress ) _iprintf (" ClipEventPress");
  if ( clipevflags->ClipEventInitialize ) _iprintf (" ClipEventInitialize");
  if ( clipevflags->ClipEventData ) _iprintf (" ClipEventData");
  if ( clipevflags->ClipEventConstruct ) _iprintf (" ClipEventConstruct");
  if ( clipevflags->ClipEventKeyPress ) _iprintf (" ClipEventKeyPress");
  if ( clipevflags->ClipEventDragOut ) _iprintf (" ClipEventDragOut");
}

void
outputSWF_CLIPACTIONRECORD (SWF_CLIPACTIONRECORD * carec )
{
#ifdef NODECOMPILE
  int i;
#endif
#if !defined(ACTIONONLY)
  _iprintf(" onClipEvents("); outputSWF_CLIPEVENTFLAGS (&carec->EventFlag); printf(" ):\n");
  /*_iprintf(" ActionRecordSize %ld\n", carec->ActionRecordSize);*/
  if ( carec->KeyCode) _iprintf(" EventKeyCode %d\n", carec->KeyCode);
#endif
#ifdef NODECOMPILE
  ++INDENT;
  /*_iprintf(" %d Actions\n", carec->numActions);*/
  for(i=0;i<carec->numActions;i++)
     outputSWF_ACTION(i,&(carec->Actions[i]));
  --INDENT;
#else
  ++INDENT;
  _iprintf (" %s\n", decompile5Action(carec->numActions,carec->Actions,0));
  --INDENT;
#endif
}

void
outputSWF_CLIPACTIONS (SWF_CLIPACTIONS * clipactions )
{
  int i;
  for(i=0;i<clipactions->NumClipRecords-1;i++)
    outputSWF_CLIPACTIONRECORD(&(clipactions->ClipActionRecords[i]));
}

void
outputSWF_GRADIENTRECORD (SWF_GRADIENTRECORD * gradientrec, char *gname)
{
  _iprintf (" Ratio: %d\n", gradientrec->Ratio);
  outputSWF_RGBA (&gradientrec->Color, "");
}

void
outputSWF_MORPHGRADIENTRECORD (SWF_MORPHGRADIENTRECORD * gradientrec, 
                               char *gname)
{
  _iprintf (" StartRatio: %d\n", gradientrec->StartRatio);
  outputSWF_RGBA (&gradientrec->StartColor, "");
  _iprintf (" EndRatio: %d\n", gradientrec->EndRatio);
  outputSWF_RGBA (&gradientrec->EndColor, "");
}

void 
outputFIXED(FIXED fixed, const char *prefix)
{
	float f;
	
	f = fixed * 1.0 / (1<<16);
	_iprintf("%s%f\n", prefix, f);
}

void 
outputFIXED8(FIXED fixed, const char *prefix)
{
	float f;
	
	f = fixed * 1.0 / (1<<8);
	_iprintf("%s%f\n", prefix, f);
}

void
outputSWF_FOCALGRADIENT (SWF_FOCALGRADIENT * gradient, char *name)
{
  int i;
  _iprintf (" Gradient: ");
  _iprintf (" SpreadMode: %d\n", gradient->SpreadMode);
  _iprintf (" InterpolationMode: %d\n", gradient->InterpolationMode);
  _iprintf (" NumGradients: %d\n", gradient->NumGradients);
  for (i = 0; i < gradient->NumGradients; i++)
    outputSWF_GRADIENTRECORD (&(gradient->GradientRecords[i]),"");
  outputFIXED8(gradient->FocalPoint, "  FocalPoint: ");
}

void
outputSWF_GRADIENT (SWF_GRADIENT * gradient, char *name)
{
  int i;
  _iprintf (" Gradient: ");
  _iprintf (" SpreadMode: %d\n", gradient->SpreadMode);
  _iprintf (" InterpolationMode: %d\n", gradient->InterpolationMode);
  _iprintf (" NumGradients: %d\n", gradient->NumGradients);
  for (i = 0; i < gradient->NumGradients; i++)
    outputSWF_GRADIENTRECORD (&(gradient->GradientRecords[i]),"");
}

void
outputSWF_MORPHGRADIENT (SWF_MORPHGRADIENT * gradient, char *name)
{
  int i;
  _iprintf (" MorphGradient: ");
  _iprintf (" NumGradients: %d\n", gradient->NumGradients);
  for (i = 0; i < gradient->NumGradients; i++)
    outputSWF_MORPHGRADIENTRECORD (&(gradient->GradientRecords[i]),"");
}


void
outputSWF_FILLSTYLE (SWF_FILLSTYLE * fillstyle, char *name, int i)
{
  _iprintf (" FillStyle: ");
  _iprintf (" FillStyleType: %x\n", fillstyle->FillStyleType);
  switch (fillstyle->FillStyleType)
    {
    case 0x00:			/* Solid Fill */
      outputSWF_RGBA (&fillstyle->Color, "");
      break;
    case 0x10:			/* Linear Gradient Fill */
    case 0x12:			/* Radial Gradient Fill */
      outputSWF_MATRIX (&fillstyle->GradientMatrix,"");
      outputSWF_GRADIENT (&fillstyle->Gradient,"");
      break;
    case 0x13:
      outputSWF_MATRIX (&fillstyle->GradientMatrix,"");
      outputSWF_FOCALGRADIENT(&fillstyle->FocalGradient, "");
    case 0x40:			/* Repeating Bitmap Fill */
    case 0x41:			/* Clipped Bitmap Fill */
    case 0x42:			/* Non-smoothed Repeating Bitmap Fill */
    case 0x43:			/* Non-smoothed Clipped Bitmap Fill */
      _iprintf (" BitmapID: %d\n", fillstyle->BitmapId);
      outputSWF_MATRIX (&fillstyle->BitmapMatrix,"");
      break;
    }
}

void
outputSWF_FILLSTYLEARRAY (SWF_FILLSTYLEARRAY * fillstylearray, char *name)
{
  int count, i;

  _iprintf (" FillStyleArray: ");
  _iprintf (" FillStyleCount: %6d ", fillstylearray->FillStyleCount);
  _iprintf (" FillStyleCountExtended: %6d\n",
	  fillstylearray->FillStyleCountExtended);
  count =
    (fillstylearray->FillStyleCount !=
     0xff) ? fillstylearray->FillStyleCount : fillstylearray->
    FillStyleCountExtended;
  for (i = 0; i < count; i++)
    {
      outputSWF_FILLSTYLE (&(fillstylearray->FillStyles[i]),"",0);
    }
}

void
outputSWF_MORPHFILLSTYLE (SWF_MORPHFILLSTYLE * fillstyle, char *name, 
                          int i)
{
  _iprintf (" MorphFillStyle: ");
  _iprintf (" FillStyleType: %x\n", fillstyle->FillStyleType);
  switch (fillstyle->FillStyleType)
    {
    case 0x00:			/* Solid Fill */
      outputSWF_RGBA (&fillstyle->StartColor, "");
      outputSWF_RGBA (&fillstyle->EndColor, "");
      break;
    case 0x10:			/* Linear Gradient Fill */
    case 0x12:			/* Radial Gradient Fill */
      outputSWF_MATRIX (&fillstyle->StartGradientMatrix,"");
      outputSWF_MATRIX (&fillstyle->EndGradientMatrix,"");
      outputSWF_MORPHGRADIENT (&fillstyle->Gradient,"");
      break;
    case 0x40:			/* Repeating Bitmap Fill */
    case 0x41:			/* Clipped Bitmap Fill */
    case 0x42:			/* Non-smoothed Repeating Bitmap Fill */
    case 0x43:			/* Non-smoothed Clipped Bitmap Fill */
      _iprintf (" BitmapID: %d\n", fillstyle->BitmapId);
      outputSWF_MATRIX (&fillstyle->StartBitmapMatrix,"");
      outputSWF_MATRIX (&fillstyle->EndBitmapMatrix,"");
      break;
    }
}

void
outputSWF_MORPHFILLSTYLES( SWF_MORPHFILLSTYLES *fillstylearray)
{
  int count, i;

  if( !verbose ) 
	return;
  _iprintf (" MorphFillStyleArray: ");
  _iprintf (" FillStyleCount: %6d ", fillstylearray->FillStyleCount);
  _iprintf (" FillStyleCountExtended: %6d\n",
          fillstylearray->FillStyleCountExtended);
  count =
    (fillstylearray->FillStyleCount !=
     0xff) ? fillstylearray->FillStyleCount : fillstylearray->
    FillStyleCountExtended;
  for (i = 0; i < count; i++)
    { 
      outputSWF_MORPHFILLSTYLE (&(fillstylearray->FillStyles[i]),"",0);
    }
}


void
outputSWF_LINESTYLE (SWF_LINESTYLE * fillstyle, char *name, int i)
{
  _iprintf (" LineStyle: ");
  _iprintf (" Width: %d\n", fillstyle->Width);
  outputSWF_RGBA (&fillstyle->Color, "");
}

void
outputSWF_LINESTYLE2 (SWF_LINESTYLE2 * fillstyle, char *name, int i)
{
  _iprintf (" LineStyle2: ");
  _iprintf (" Width: %d\n", fillstyle->Width);
  _iprintf (" StartCapStyle: %d\n", fillstyle->StartCapStyle);
  _iprintf (" JoinStyle: %d\n", fillstyle->JoinStyle);
  _iprintf (" HasFillFlag: %d\n", fillstyle->HasFillFlag);
  _iprintf (" NoHScaleFlag: %d\n", fillstyle->NoHScaleFlag);
  _iprintf (" NoVScaleFlag: %d\n", fillstyle->NoVScaleFlag);
  _iprintf (" PixelHintingFlag %d\n", fillstyle->PixelHintingFlag);
  _iprintf (" NoClose %d\n", fillstyle->NoClose);
  _iprintf (" EndCapStyle %d\n", fillstyle->EndCapStyle);
  if(fillstyle->JoinStyle == 2)
    _iprintf (" MiterLimitFactor %d\n", fillstyle->MiterLimitFactor);
  if(fillstyle->HasFillFlag == 0)
    outputSWF_RGBA (&fillstyle->Color, "");
  else
    outputSWF_FILLSTYLE (&fillstyle->FillType, "", 0);
}

void
outputSWF_LINESTYLEARRAY (SWF_LINESTYLEARRAY * linestylearray, char *name)
{

  int count, i;

  count = linestylearray->LineStyleCount;

  _iprintf (" LineStyleArray: ");
  _iprintf (" LineStyleCount: %d\n", count);

  for (i = 0; i < count; i++)
  {
    if(linestylearray->LineStyles != NULL)   
      outputSWF_LINESTYLE (&(linestylearray->LineStyles[i]),"",0);
    else if(linestylearray->LineStyles2 != NULL)
      outputSWF_LINESTYLE2 (&(linestylearray->LineStyles2[i]),"",0);
    else
      _iprintf("LineStyleArray: parser error\n");
  }
}

void
outputSWF_MORPHLINESTYLE (SWF_MORPHLINESTYLE * linestyle, char *name)
{
  _iprintf (" MorphLineStyle: ");
  _iprintf (" StartWidth: %d\n", linestyle->StartWidth);
  _iprintf (" EndWidth: %d\n", linestyle->EndWidth);
  outputSWF_RGBA (&linestyle->StartColor, "");
  outputSWF_RGBA (&linestyle->EndColor, "");
}

void
outputSWF_MORPHLINESTYLE2 (SWF_MORPHLINESTYLE2 * linestyle, char *name)
{
  _iprintf (" MorphLineStyle2: ");
  _iprintf (" StartWidth: %d\n", linestyle->StartWidth);
  _iprintf (" EndWidth: %d\n", linestyle->EndWidth);
  _iprintf (" StartCapStyle: %d\n", linestyle->StartCapStyle);
  _iprintf (" JoinStyle: %d\n", linestyle->JoinStyle);
  _iprintf (" HasFillFlag: %d\n", linestyle->HasFillFlag);
  _iprintf (" NoHScaleFlag: %d\n", linestyle->NoHScaleFlag);
  _iprintf (" NoVScaleFlag: %d\n", linestyle->NoVScaleFlag);
  _iprintf (" PixelHintingFlag %d\n", linestyle->PixelHintingFlag);
  _iprintf (" NoClose %d\n", linestyle->NoClose);
  _iprintf (" EndCapStyle %d\n", linestyle->EndCapStyle);
  if(linestyle->JoinStyle == 2)
    _iprintf (" MiterLimitFactor %d\n", linestyle->MiterLimitFactor);
  if(linestyle->HasFillFlag == 0) {
    outputSWF_RGBA (&linestyle->StartColor, "");
    outputSWF_RGBA (&linestyle->EndColor, "");
  }
  else
    outputSWF_MORPHFILLSTYLE (&linestyle->FillType, "", 0);
}

void
outputSWF_MORPHLINESTYLES (SWF_MORPHLINESTYLES * linestylearray)
{

  int count, i;

  if( !verbose ) return;
  _iprintf (" MorphLineStyleArray: ");
  _iprintf (" LineStyleCount: %6d ", linestylearray->LineStyleCount);
  _iprintf (" LineStyleCountExtended: %6d\n",
	  linestylearray->LineStyleCountExtended);
  count =
    (linestylearray->LineStyleCount !=
     0xff) ? linestylearray->LineStyleCount : linestylearray->
    LineStyleCountExtended;
  for (i = 0; i < count; i++)
  {
    if(linestylearray->LineStyles != NULL)   
      outputSWF_MORPHLINESTYLE (&(linestylearray->LineStyles[i]),"");
    else if(linestylearray->LineStyles2 != NULL)
      outputSWF_MORPHLINESTYLE2 (&(linestylearray->LineStyles2[i]),"");
    else
      _iprintf("LineStyleArray: parser error\n");
  }
}

void
outputSWF_SHAPERECORD (SWF_SHAPERECORD * shaperec, char *parentname)
{
  if (shaperec->EndShape.TypeFlag)
    {
      /* An Edge Record */
      if (shaperec->StraightEdge.StraightEdge == 1)
	{
	  /* A Straight Edge Record */
	  _iprintf (" Straight EdgeRecord: (%d)",
		  shaperec->StraightEdge.NumBits);
	  if( shaperec->StraightEdge.GeneralLineFlag ) {
		  _iprintf(" - (%ld, %ld)\n",shaperec->StraightEdge.DeltaX,shaperec->StraightEdge.DeltaY);
	  } else {
	  	if( shaperec->StraightEdge.VertLineFlag ) 
		  _iprintf(" - (0, %ld)\n",shaperec->StraightEdge.VLDeltaY);
		else
		  _iprintf(" - (%ld, 0)\n",shaperec->StraightEdge.VLDeltaX);
	  }
	}
      else
	{
	  /* A Curved Edge Record */
	  _iprintf (" Curved EdgeRecord: %d", shaperec->CurvedEdge.NumBits);
	  _iprintf (" Control(%ld,%ld)", shaperec->CurvedEdge.ControlDeltaX,
		  shaperec->CurvedEdge.ControlDeltaY);
	  _iprintf (" Anchor(%ld,%ld)\n", shaperec->CurvedEdge.AnchorDeltaX,
		  shaperec->CurvedEdge.AnchorDeltaY);
	}
    }
  else
    {
      /* A Non-Edge Record */
      if (shaperec->EndShape.EndOfShape == 0)
	{
	  _iprintf ("  ENDSHAPE\n");
	  return;
	}
      _iprintf (" StyleChangeRecord:\n");
      _iprintf ("  StateNewStyles: %d", shaperec->StyleChange.StateNewStyles);
      _iprintf (" StateLineStyle: %d ", shaperec->StyleChange.StateLineStyle);
      _iprintf (" StateFillStyle1: %d\n",
	      shaperec->StyleChange.StateFillStyle1);
      _iprintf ("  StateFillStyle0: %d",
	      shaperec->StyleChange.StateFillStyle0);
      _iprintf (" StateMoveTo: %d\n", shaperec->StyleChange.StateMoveTo);

      if (shaperec->StyleChange.StateLineStyle) {
	  _iprintf ("   LineStyle: %ld\n", shaperec->StyleChange.LineStyle);
      }
      if (shaperec->StyleChange.StateFillStyle1) {
	  _iprintf ("   FillStyle1: %ld\n", shaperec->StyleChange.FillStyle1);
      }
      if (shaperec->StyleChange.StateFillStyle0) {
	  _iprintf ("   FillStyle0: %ld\n", shaperec->StyleChange.FillStyle0);
      }
      if (shaperec->StyleChange.StateMoveTo)
	{
	  _iprintf ("   MoveBits: %d ", shaperec->StyleChange.MoveBits);
	  _iprintf (" MoveDeltaX: %ld ", shaperec->StyleChange.MoveDeltaX);
	  _iprintf (" MoveDeltaY: %ld\n", shaperec->StyleChange.MoveDeltaY);
	}
    }
}

void
outputSWF_SHAPE (SWF_SHAPE * shape, char *name)
{
  int i;
  _iprintf (" %s\n", name );
  _iprintf (" NumFillBits: %d\n", shape->NumFillBits);
  _iprintf (" NumLineBits: %d\n", shape->NumLineBits);
  for (i = 0; i < shape->NumShapeRecords; i++)
    {
      outputSWF_SHAPERECORD (&(shape->ShapeRecords[i]), name);
    }
}

void
outputSWF_SHAPEWITHSTYLE (SWF_SHAPEWITHSTYLE * shape, int level, char *name)
{
  int i;

  outputSWF_FILLSTYLEARRAY (&(shape->FillStyles),"");
  outputSWF_LINESTYLEARRAY (&(shape->LineStyles),"");
  _iprintf (" NumFillBits: %d\n", shape->NumFillBits);
  _iprintf (" NumLineBits: %d\n", shape->NumLineBits);
  for (i = 0; i < shape->NumShapeRecords; i++)
    {
      outputSWF_SHAPERECORD (&(shape->ShapeRecords[i]),name);
    }
}

void
outputSWF_GLYPHENTRY (SWF_GLYPHENTRY *gerec)
{
	_iprintf("   GlyphIndex[0] = %4.4lx ", gerec->GlyphIndex[0] );
	_iprintf("   GlyphAdvance[0] = %4.4lx\n", gerec->GlyphAdvance[0] );
}

void
outputSWF_TEXTRECORD (SWF_TEXTRECORD *trec, int level)
{
  int i;
  _iprintf (" TEXTRECORD: ");
  _iprintf ("  TextRecordType: %d ", trec->TextRecordType);
  _iprintf ("  StyleFlagsReserved: %d ", trec->StyleFlagsReserved);
  _iprintf ("  StyleFlagHasFont: %d ", trec->StyleFlagHasFont);
  _iprintf ("  StyleFlagHasColor: %d ", trec->StyleFlagHasColor);
  _iprintf ("  StyleFlagHasYOffset: %d ", trec->StyleFlagHasYOffset);
  _iprintf ("  StyleFlagHasXOffset: %d\n", trec->StyleFlagHasXOffset);

  if ( trec->TextRecordType == 0 )
  {
  	/*
	 * parser doesn't initialize any other
	 * member when TextRecordType == 0,
	 * see parseSWF_TEXTRECORD in parser.c
	 */
  	return;
  }

  if( trec->StyleFlagHasFont )
    _iprintf ("  FontID: %d\n", trec->FontID);
  if( trec->StyleFlagHasColor ) {
    outputSWF_RGBA(&trec->TextColor, "" );
  }
  if( trec->StyleFlagHasYOffset || trec->StyleFlagHasXOffset ) {
    _iprintf ("  XOffset: %d ", trec->XOffset);
    _iprintf ("  YOffset: %d\n", trec->YOffset);
  }
  if( trec->StyleFlagHasFont )
    _iprintf ("  TextHeight: %d\n", trec->TextHeight);
  _iprintf ("  GlyphCount: %d\n", trec->GlyphCount);
  for(i=0;i<trec->GlyphCount;i++)
	  outputSWF_GLYPHENTRY( &(trec->GlyphEntries[i]) );
}

void 
outputSWF_BLURFILTER(SWF_BLURFILTER *filter)
{
	outputFIXED(filter->BlurX, "    BlurX: ");
        outputFIXED(filter->BlurY, "    BlurY: ");
	_iprintf("    Passes %d\n", filter->Passes);
}

void 
outputSWF_BEVELFILTER(SWF_BEVELFILTER *filter)
{
	outputSWF_RGBA (&filter->ShadowColor, "    ShadowColor:");
	outputSWF_RGBA (&filter->HighlightColor, "    HighLightColor:");
	outputFIXED(filter->BlurX, "    BlurX: ");
        outputFIXED(filter->BlurY, "    BlurY: ");
        outputFIXED(filter->Angle, "    Angle: ");
        outputFIXED(filter->Distance, "    Distance: ");
        outputFIXED8(filter->Strength, "    Strength: ");
        _iprintf("    InnerShadow: %d\n", filter->InnerShadow);
        _iprintf("    Kockout %d\n", filter->Kockout);
        _iprintf("    CompositeSource %d\n", filter->CompositeSource);
        _iprintf("    OnTop: %d\n", filter->OnTop);
        _iprintf("    Passes %d\n", filter->Passes);
}

void
outputSWF_GRADIENTFILTER(SWF_GRADIENTFILTER *filter)
{
	int i;
	_iprintf("    NumColor %d\n", filter->NumColors);
	for(i = 0; i < filter->NumColors; i++)
	{
		outputSWF_RGBA (filter->GradientColors + i, "    ");
		_iprintf("    Ratio: %d\n", filter->GradientRatio[i]);
	}
	outputFIXED(filter->BlurX, "    BlurX: ");
        outputFIXED(filter->BlurY, "    BlurY: ");
        outputFIXED(filter->Angle, "    Angle: ");
        outputFIXED(filter->Distance, "    Distance: ");
        outputFIXED8(filter->Strength, "    Strength: ");
	_iprintf("    InnerShadow: %d\n", filter->InnerShadow);
        _iprintf("    Kockout %d\n", filter->Kockout);
        _iprintf("    CompositeSource %d\n", filter->CompositeSource);
	_iprintf("    OnTop: %d\n", filter->OnTop);
        _iprintf("    Passes %d\n", filter->Passes);
}

void 
outputSWF_DROPSHADOWFILTER(SWF_DROPSHADOWFILTER *filter)
{
	outputSWF_RGBA (&filter->DropShadowColor, "    DropShadowColor:");
	outputFIXED(filter->BlurX, "    BlurX: ");
	outputFIXED(filter->BlurY, "    BlurY: ");
	outputFIXED(filter->Angle, "    Angle: ");
	outputFIXED(filter->Distance, "    Distance: ");
	outputFIXED8(filter->Strength, "    Strength: ");
	_iprintf("    InnerShadow: %d\n", filter->InnerShadow);
	_iprintf("    Kockout %d\n", filter->Kockout);
	_iprintf("    CompositeSource %d\n", filter->CompositeSource);
	_iprintf("    Passes %d\n", filter->Passes);
}

void 
outputSWF_GLOWFILTER(SWF_GLOWFILTER *filter)
{
	outputSWF_RGBA (&filter->GlowColor, "");
	outputFIXED(filter->BlurX, "    BlurX: ");
	outputFIXED(filter->BlurY, "    BlurY: ");
	outputFIXED8(filter->Strength, "    Strength: ");
	_iprintf("    InnerGlow: %d\n", filter->InnerGlow);
	_iprintf("    Kockout %d\n", filter->Kockout);
	_iprintf("    CompositeSource %d\n", filter->CompositeSource);
	_iprintf("    Passes %d\n", filter->Passes);
}

void 
outputSWF_CONVOLUTIONFILTER(SWF_CONVOLUTIONFILTER *filter)
{
	int y, x;

	_iprintf("    Matrix %dx%d\n", filter->MatrixX, filter->MatrixY);
	_iprintf("      Bias %f, Divisor %f\n", filter->Bias, filter->Divisor);
	for(y = 0; y < filter->MatrixY; y++)
	{
		_iprintf("    ");
		for(x = 0; x < filter->MatrixX; x++)
		{
			FLOAT val = filter->Matrix[y * filter->MatrixX + x];
			_iprintf("%f ", val);
		}
		_iprintf("\n");
	}
	outputSWF_RGBA (&filter->DefaultColor, "     efault Color: ");
	_iprintf("    Clamp: %d\n", filter->Clamp);
	_iprintf("    PreserveAlpha: %d\n", filter->PreserveAlpha);
}

void 
outputSWF_COLORMATRIXFILTER(SWF_COLORMATRIXFILTER *filter)
{
	int y, x;

	for(y = 0; y < 4; y++)
        {
                _iprintf("    ");
                for(x = 0; x < 5; x++)
                {
                        FLOAT val = filter->Matrix[y * 5 + x];
                        _iprintf("%f ", val);
                }
                _iprintf("\n");
        }
}

void 
outputSWF_FILTER(SWF_FILTER *filter)
{
	switch(filter->FilterId)
	{
		case FILTER_DROPSHADOW:
			_iprintf("  Filter: DropShadow\n");
			outputSWF_DROPSHADOWFILTER(&filter->filter.dropShadow);
			break;
		case FILTER_BLUR:
			_iprintf("  Filter: Blur\n");
			outputSWF_BLURFILTER(&filter->filter.blur);
			break;
		case FILTER_GLOW:
			_iprintf("  Filter: Glow\n");
			outputSWF_GLOWFILTER(&filter->filter.glow);
			break;
		case FILTER_BEVEL:
			_iprintf("  Filter: Bevel\n");
			outputSWF_BEVELFILTER(&filter->filter.bevel);
			break;
		case FILTER_GRADIENTGLOW:
			_iprintf("  Filter: GradientGlow\n");
			outputSWF_GRADIENTFILTER(&filter->filter.gradientGlow);
			break;
		case FILTER_CONVOLUTION:
			_iprintf("  Filter: Convolution\n");
			outputSWF_CONVOLUTIONFILTER(&filter->filter.convolution);
			break;
		case FILTER_COLORMATRIX:
			_iprintf("  Filter: ColorMatrix\n");
			outputSWF_COLORMATRIXFILTER(&filter->filter.colorMatrix);
			break;
		case FILTER_GRADIENTBEVEL:
			_iprintf("  Filter: GradientBevel\n");
			outputSWF_GRADIENTFILTER(&filter->filter.gradientBevel);
			break;
		default:
			_iprintf("  Filter: Unknown %d\n", filter->FilterId);
	}
}

/* Output Flash Blocks */

void
outputSWF_CHARACTERSET (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_CHARACTERSET);

}

void
outputSWF_DEFINEBITS (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINEBITS);
  _iprintf(" CharacterID: %d\n", sblock->CharacterID);
}

void
outputSWF_DEFINEBITSJPEG2 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINEBITSJPEG2);
  _iprintf(" CharacterID: %d\n", sblock->CharacterID);
}

void
outputSWF_DEFINEBITSJPEG3 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINEBITSJPEG3);
  _iprintf(" CharacterID: %d\n", sblock->CharacterID);
  _iprintf(" AlphaDataOffset %d\n", sblock->AlphaDataOffset);
}

void
outputSWF_DEFINEBITSPTR (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_DEFINEBITSPTR);

}

void
outputSWF_DEFINEBUTTON (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_DEFINEBUTTON);

}

void
outputSWF_DEFINEBUTTON2 (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_DEFINEBUTTON2);

#if !defined(ACTIONONLY)
  _iprintf (" CharacterID: %d\n", sblock->Buttonid);
  _iprintf (" TrackAsMenu: %d\n", sblock->TrackAsMenu);
  _iprintf (" ActionOffset: %d\n", sblock->ActionOffset);
  for(i=0;i<sblock->numCharacters;i++) {
	  outputSWF_BUTTONRECORD( &(sblock->Characters[i]) );
  }
#endif
  for(i=0;i<sblock->numActions;i++) {
	  outputSWF_BUTTONCONDACTION( &(sblock->Actions[i]) );
  }

}

void
outputSWF_DEFINEBUTTONCXFORM (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINEBUTTONCXFORM);
  _iprintf(" ButtonId %d\n", sblock->ButtonId);
  outputSWF_CXFORM(&sblock->ButtonColorTransform);
}

void 
outputSWF_SOUNDINFO (SWF_SOUNDINFO *info);

void
outputSWF_DEFINEBUTTONSOUND (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINEBUTTONSOUND);
  _iprintf(" CharacterID: %d\n", sblock->CharacterID);
  _iprintf(" ButtonSoundChar0 %d\n", sblock->ButtonSoundChar0);
  if(sblock->ButtonSoundChar0)
    outputSWF_SOUNDINFO (&sblock->ButtonSoundInfo0);
  
  _iprintf(" ButtonSoundChar1 %d\n", sblock->ButtonSoundChar1);
  if(sblock->ButtonSoundChar1)
    outputSWF_SOUNDINFO (&sblock->ButtonSoundInfo1);
  
  _iprintf(" ButtonSoundChar2 %d\n", sblock->ButtonSoundChar2);
  if(sblock->ButtonSoundChar2)
    outputSWF_SOUNDINFO (&sblock->ButtonSoundInfo2);
  
  _iprintf(" ButtonSoundChar3 %d\n", sblock->ButtonSoundChar3);
  if(sblock->ButtonSoundChar3)
    outputSWF_SOUNDINFO (&sblock->ButtonSoundInfo3);
}

void
outputSWF_DEFINECOMMANDOBJ (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_DEFINECOMMANDOBJ);

}

void
outputSWF_DEFINEEDITTEXT (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINEEDITTEXT);

  _iprintf (" CharacterID: %d\n", sblock->CharacterID);
  outputSWF_RECT (&(sblock->Bounds));
  _iprintf (" Flags: ");
  _iprintf (" HasText: %d ", sblock->HasText);
  _iprintf (" WordWrap: %d ", sblock->WordWrap);
  _iprintf (" Multiline: %d ", sblock->Multiline);
  _iprintf (" Password: %d ", sblock->Password);
  _iprintf (" ReadOnly: %d\n", sblock->ReadOnly);
  _iprintf ("        ");
  _iprintf (" HasTextColor: %d ", sblock->HasTextColor);
  _iprintf (" HasMaxLength: %d ", sblock->HasMaxLength);
  _iprintf (" HasFont: %d ", sblock->HasFont);
  _iprintf (" HasFontClass: %d ", sblock->HasFontClass);
  _iprintf (" AutoSize: %d ", sblock->AutoSize);
  _iprintf (" HasLayout: %d\n", sblock->HasLayout);
  _iprintf ("        ");
  _iprintf (" NoSelect: %d ", sblock->NoSelect);
  _iprintf (" Border: %d ", sblock->Border);
  _iprintf (" WasStatic: %d ", sblock->WasStatic);
  _iprintf (" HTML: %d ", sblock->HTML);
  _iprintf (" UseOutlines: %d\n", sblock->UseOutlines);
  if (sblock->HasFont)
    {
      _iprintf (" Font: ");
      _iprintf (" FontID: %d ", sblock->FontID);
      _iprintf (" FontHeight: %d\n", sblock->FontHeight);
    }

  if (sblock->HasFontClass)
    _iprintf(" FontClass: %s\n", sblock->FontClass);

  if (sblock->HasTextColor)
    {
      outputSWF_RGBA (&sblock->TextColor,"");
    }
  if (sblock->HasLayout)
    {
      _iprintf (" Layout:: ");
      _iprintf (" Align: %d ", sblock->Align);
      _iprintf (" LeftMargin: %d ", sblock->LeftMargin);
      _iprintf (" RightMargin: %d ", sblock->RightMargin);
      _iprintf (" Indent: %d ", sblock->Indent);
      _iprintf (" Leading: %d\n", sblock->Leading);
    }
  _iprintf (" VariableName: %s\n", sblock->VariableName);
  if (sblock->HasText)
    {
      _iprintf (" InitialText: %s\n", sblock->InitialText);
    }
}

void
outputSWF_DEFINEFONT (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_DEFINEFONT);
  _iprintf (" FontID: %d\n", sblock->FontID);
  for (i = 0; i < sblock->NumGlyphs; i++)
    _iprintf (" OffsetTable[%3.3d]: %x\n", i, sblock->OffsetTable[i]);
  
  for (i = 0; i < sblock->NumGlyphs; i++)
    {
	char shapename[32];
	sprintf(shapename,"Shape[%3.3d]",i);
	outputSWF_SHAPE (&(sblock->GlyphShapeTable[i]), shapename);
    }
}

void
outputSWF_DEFINEFONT2 (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_DEFINEFONT2);

  _iprintf (" FontID: %d\n", sblock->FontID);
  _iprintf (" FontFlagsHasLayout: %d\n", sblock->FontFlagsHasLayout);
  _iprintf (" FontFlagsShiftJis: %d\n", sblock->FontFlagsShiftJis);
  _iprintf (" FontFlagsSmallText: %d\n", sblock->FontFlagsSmallText);
  _iprintf (" FontFlagsFlagANSI: %d\n", sblock->FontFlagsFlagANSI);
  _iprintf (" FontFlagsWideOffsets: %d\n", sblock->FontFlagsWideOffsets);
  _iprintf (" FontFlagsWideCodes: %d\n", sblock->FontFlagsWideCodes);
  _iprintf (" FontFlagsFlagsItalics: %d\n", sblock->FontFlagsFlagsItalics);
  _iprintf (" FontFlagsFlagsBold: %d\n", sblock->FontFlagsFlagsBold);
  _iprintf (" LanguageCode: %d\n", sblock->LanguageCode);
  _iprintf (" FontNameLen: %d\n", sblock->FontNameLen);
  _iprintf (" FontName: %s\n", sblock->FontName);
  _iprintf (" NumGlyphs: %d\n", sblock->NumGlyphs);
  for (i = 0; i < sblock->NumGlyphs; i++)
    {
      if (sblock->FontFlagsWideOffsets)
	{
	  _iprintf (" OffsetTable[%3.3d]: %lx\n", i,
		  sblock->OffsetTable.UI32[i]);
	}
      else
	{
	  _iprintf (" OffsetTable[%3.3d]: %x\n", i,
		  sblock->OffsetTable.UI16[i]);
	}
    }
  if (sblock->FontFlagsWideOffsets)
    {
      _iprintf (" CodeTableOffset: %lx\n", sblock->CodeTableOffset.UI32);
    }
  else
    {
      _iprintf (" CodeTableOffset: %x\n", sblock->CodeTableOffset.UI16);
    }

  for (i = 0; i < sblock->NumGlyphs; i++)
    {
	char shapename[32];
	sprintf(shapename,"Shape[%3.3d]",i);
	outputSWF_SHAPE (&(sblock->GlyphShapeTable[i]), shapename);
    }

  for (i = 0; i < sblock->NumGlyphs; i++)
    {
	if( sblock->FontFlagsWideCodes )
	  {
		_iprintf (" CodeTable[%3.3d]: %4.4x\n", i,
		  	sblock->CodeTable[i]);
	  }
	else
	  {
		_iprintf (" CodeTable[%3.3d]: %2.2x\n", i,
		  	sblock->CodeTable[i]);
	  }
    }

  if( sblock->FontFlagsHasLayout ) {
    _iprintf (" FontAscent: %d\n", sblock->FontAscent);
    _iprintf (" FontDecent: %d\n", sblock->FontDecent);
    _iprintf (" FontLeading: %d\n", sblock->FontLeading);
    for (i = 0; i < sblock->NumGlyphs; i++)
      {
	_iprintf (" FontAdvanceTable[%3.3d]: %x\n", i,
		  sblock->FontAdvanceTable[i]);
      }
    _iprintf (" FontBoundsTable: (not used)\n");
    for (i = 0; i < sblock->NumGlyphs; i++)
      {
	outputSWF_RECT (&(sblock->FontBoundsTable[i]));
      }
    _iprintf (" KerningCount: %d\n", sblock->KerningCount);
    for (i = 0; i < sblock->KerningCount; i++)
      {
	_iprintf (" FontKerningTable[%3.3d]: %d,%d %d\n", i,
		  sblock->FontKerningTable[i].FontKerningCode1,
		  sblock->FontKerningTable[i].FontKerningCode2,
		  sblock->FontKerningTable[i].FontKerningAdjustment);
      }
  }

}

void
outputSWF_DEFINEFONT3 (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_DEFINEFONT3);

  _iprintf (" FontID: %d\n", sblock->FontID);
  _iprintf (" FontFlagsHasLayout: %d\n", sblock->FontFlagsHasLayout);
  _iprintf (" FontFlagsShiftJis: %d\n", sblock->FontFlagsShiftJis);
  _iprintf (" FontFlagsSmallText: %d\n", sblock->FontFlagsSmallText);
  _iprintf (" FontFlagsFlagANSI: %d\n", sblock->FontFlagsFlagANSI);
  _iprintf (" FontFlagsWideOffsets: %d\n", sblock->FontFlagsWideOffsets);
  _iprintf (" FontFlagsWideCodes: %d\n", sblock->FontFlagsWideCodes);
  _iprintf (" FontFlagsFlagsItalics: %d\n", sblock->FontFlagsFlagsItalics);
  _iprintf (" FontFlagsFlagsBold: %d\n", sblock->FontFlagsFlagsBold);
  _iprintf (" LanguageCode: %d\n", sblock->LanguageCode);
  _iprintf (" FontNameLen: %d\n", sblock->FontNameLen);
  _iprintf (" FontName: %s\n", sblock->FontName);
  _iprintf (" NumGlyphs: %d\n", sblock->NumGlyphs);
  for (i = 0; i < sblock->NumGlyphs; i++)
    {
      if (sblock->FontFlagsWideOffsets)
	{
	  _iprintf (" OffsetTable[%3.3d]: %lx\n", i,
		  sblock->OffsetTable.UI32[i]);
	}
      else
	{
	  _iprintf (" OffsetTable[%3.3d]: %x\n", i,
		  sblock->OffsetTable.UI16[i]);
	}
    }
  if (sblock->FontFlagsWideOffsets)
    {
      _iprintf (" CodeTableOffset: %lx\n", sblock->CodeTableOffset.UI32);
    }
  else
    {
      _iprintf (" CodeTableOffset: %x\n", sblock->CodeTableOffset.UI16);
    }

  for (i = 0; i < sblock->NumGlyphs; i++)
    {
	char shapename[32];
	sprintf(shapename,"Shape[%3.3d]",i);
	outputSWF_SHAPE (&(sblock->GlyphShapeTable[i]), shapename);
    }

  for (i = 0; i < sblock->NumGlyphs; i++)
    {
	if( sblock->FontFlagsWideCodes )
	  {
		_iprintf (" CodeTable[%3.3d]: %4.4x\n", i,
		  	sblock->CodeTable[i]);
	  }
	else
	  {
		_iprintf (" CodeTable[%3.3d]: %2.2x\n", i,
		  	sblock->CodeTable[i]);
	  }
    }

  if( sblock->FontFlagsHasLayout ) {
    _iprintf (" FontAscent: %d\n", sblock->FontAscent);
    _iprintf (" FontDecent: %d\n", sblock->FontDecent);
    _iprintf (" FontLeading: %d\n", sblock->FontLeading);
    for (i = 0; i < sblock->NumGlyphs; i++)
      {
	_iprintf (" FontAdvanceTable[%3.3d]: %x\n", i,
		  sblock->FontAdvanceTable[i]);
      }
    _iprintf (" FontBoundsTable: (not used)\n");
    for (i = 0; i < sblock->NumGlyphs; i++)
      {
	outputSWF_RECT (&(sblock->FontBoundsTable[i]));
      }
    _iprintf (" KerningCount: %d\n", sblock->KerningCount);
    for (i = 0; i < sblock->KerningCount; i++)
      {
	_iprintf (" FontKerningTable[%3.3d]: %d,%d %d\n", i,
		  sblock->FontKerningTable[i].FontKerningCode1,
		  sblock->FontKerningTable[i].FontKerningCode2,
		  sblock->FontKerningTable[i].FontKerningAdjustment);
      }
  }

}

void
outputSWF_DEFINEFONTINFO (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_DEFINEFONTINFO);
  _iprintf("FontID: %d\n", sblock->FontID);
  _iprintf("FontNameLen %d\n", sblock->FontNameLen);
  _iprintf("FontName %s\n", sblock->FontName);
  _iprintf("FontFlagsSmallText %d\n", sblock->FontFlagsSmallText);
  _iprintf("FontFlagsShiftJIS %d\n", sblock->FontFlagsShiftJIS);
  _iprintf("FontFlagsANSI %d\n", sblock->FontFlagsANSI);
  _iprintf("FontFlagsItalic %d\n", sblock->FontFlagsItalic);
  _iprintf("FontFlagsBold %d\n", sblock->FontFlagsBold);
  _iprintf("FontFlagsWideCodes %d\n", sblock->FontFlagsWideCodes);
  
  if(!verbose)
	return;

  for (i = 0; i < sblock->nGlyph; i++)
  	_iprintf("code table mapping: %i -> %i\n", i, sblock->CodeTable[i]);
}

void
outputSWF_DEFINEFONTINFO2 (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_DEFINEFONTINFO2);
  _iprintf("FontID: %d\n", sblock->FontID);
  _iprintf("FontNameLen %d\n", sblock->FontNameLen);
  _iprintf("FontName %s\n", sblock->FontName);
  _iprintf("FontFlagsSmallText %d\n", sblock->FontFlagsSmallText);
  _iprintf("FontFlagsShiftJIS %d\n", sblock->FontFlagsShiftJIS);
  _iprintf("FontFlagsANSI %d\n", sblock->FontFlagsANSI);
  _iprintf("FontFlagsItalic %d\n", sblock->FontFlagsItalic);
  _iprintf("FontFlagsBold %d\n", sblock->FontFlagsBold);
  _iprintf("FontFlagsWideCodes %d\n", sblock->FontFlagsWideCodes);
  _iprintf("LanguageCode %d\n", sblock->LanguageCode); 
 
  if(!verbose)
	return;

  for (i = 0; i < sblock->nGlyph; i++)
  	_iprintf("code table mapping: %i -> %i\n", i, sblock->CodeTable[i]);
}

void 
outputSWF_CSMTEXTSETTINGS (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_CSMTEXTSETTINGS);
  _iprintf("TextID: %d\n", sblock->TextID);
  _iprintf("UseFlashType %d\n", sblock->UseFlashType);
  _iprintf("GridFit %d\n", sblock->GridFit);
  _iprintf("Thickness %d\n", sblock->Thickness);
  _iprintf("Sharpness %d\n", sblock->Sharpness);
}

void 
outputSWF_ZONEDATA(int j, struct SWF_ZONEDATA *data)
{
  _iprintf("  ZoneData: %i\n", j);
  _iprintf("    AlignmentCoordinate %d\n", data->AlignmentCoordinate);
  _iprintf("    Range %d\n", data->Range);
}

void 
outputSWF_ZONERECORD(int i, struct SWF_ZONERECORD *zone)
{
	int j;
	_iprintf("ZoneRecord %d\n", i);
	_iprintf("  NumZoneData %d\n", zone->NumZoneData);
	for(j = 0; j < zone->NumZoneData; j++)
		outputSWF_ZONEDATA(j, zone->ZoneData + j);
	
	_iprintf("  ZoneMask X %d, Y %d\n", zone->ZoneMaskX, zone->ZoneMaskY);
}

void 
outputSWF_DEFINEFONTALIGNZONES (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_DEFINEFONTALIGNZONES);

  _iprintf("  FontID: %d\n", sblock->FontID);
  _iprintf("  CSMTableHint %d\n", sblock->CSMTableHint);
  _iprintf("  GlyphCount %d\n", sblock->GlyphCount);
  for(i = 0; i < sblock->GlyphCount; i++)
    outputSWF_ZONERECORD(i, sblock->ZoneTable + i);
}

void
outputSWF_DEFINEFONTNAME (SWF_Parserstruct *pblock)
{
  OUT_BEGIN(SWF_DEFINEFONTNAME);
  _iprintf(" FontId: %d\n", sblock->FontId);
  _iprintf(" FontName: %s\n", sblock->FontName);
  _iprintf(" FontCopyright %s\n", sblock->FontCopyright);
}

void
outputSWF_DEFINELOSSLESS (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINELOSSLESS);
  _iprintf(" CharacterID: %d\n", sblock->CharacterID);
  _iprintf(" Bitmap format %d\n", sblock->BitmapFormat);
  _iprintf(" Bitmap width %d x height %d\n", sblock->BitmapWidth, sblock->BitmapHeight);
  
  if(sblock->BitmapFormat == 3)
  	_iprintf(" BitmapColorTableSize %d\n", sblock->BitmapColorTableSize);
}

void
outputSWF_DEFINELOSSLESS2 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINELOSSLESS2);
  _iprintf(" CharacterID: %d\n", sblock->CharacterID);
  _iprintf(" Bitmap format %d\n", sblock->BitmapFormat);
  _iprintf(" Bitmap width %d x height %d\n", sblock->BitmapWidth, sblock->BitmapHeight);
  if(sblock->BitmapFormat == 3)                                                                                                                                                    
        _iprintf(" BitmapColorTableSize %d\n", sblock->BitmapColorTableSize);
}

void
outputSWF_DEFINEMORPHSHAPE (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINEMORPHSHAPE);
  _iprintf(" CharacterID: %d\n", sblock->CharacterID);
  outputSWF_RECT(&(sblock->StartBounds));
  outputSWF_RECT(&(sblock->EndBounds));
  _iprintf("  Offset %d\n", sblock->Offset);
  outputSWF_MORPHFILLSTYLES(&(sblock->MorphFillStyles));
  outputSWF_MORPHLINESTYLES(&(sblock->MorphLineStyles));
  outputSWF_SHAPE(&(sblock->StartEdges), "");
  outputSWF_SHAPE(&(sblock->EndEdges), "");
}

void
outputSWF_DEFINEMORPHSHAPE2 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINEMORPHSHAPE2);
  _iprintf(" CharacterID: %d\n", sblock->CharacterID);
  outputSWF_RECT(&(sblock->StartBounds));
  outputSWF_RECT(&(sblock->EndBounds));
  outputSWF_RECT(&(sblock->StartEdgeBounds));
  outputSWF_RECT(&(sblock->EndEdgeBounds));
  _iprintf("  UsesNonScalingStrokes %d\n", 
    sblock->UsesNonScalingStrokes);
  _iprintf("  UsesScalinStrokes %d\n",
    sblock->UsesScalingStrokes);
  _iprintf("  Offset %d\n", sblock->Offset);
  outputSWF_MORPHFILLSTYLES(&(sblock->MorphFillStyles));
  outputSWF_MORPHLINESTYLES(&(sblock->MorphLineStyles));
  outputSWF_SHAPE(&(sblock->StartEdges), "");
  outputSWF_SHAPE(&(sblock->EndEdges), "");
}

void
outputSWF_DEFINESHAPE (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINESHAPE);

  _iprintf (" CharacterID: %d\n", sblock->ShapeID);
  outputSWF_RECT (&(sblock->ShapeBounds));
  outputSWF_SHAPEWITHSTYLE (&(sblock->Shapes),1,"");
}

void
outputSWF_DEFINESHAPE2 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINESHAPE2);

  _iprintf (" CharacterID: %d\n", sblock->ShapeID);
  outputSWF_RECT (&(sblock->ShapeBounds));
  outputSWF_SHAPEWITHSTYLE (&(sblock->Shapes),2,"");

}

void
outputSWF_DEFINESHAPE3 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINESHAPE3);

  _iprintf (" CharacterID: %d\n", sblock->ShapeID);
  outputSWF_RECT (&(sblock->ShapeBounds));
  outputSWF_SHAPEWITHSTYLE (&(sblock->Shapes),2,"");

}

void
outputSWF_DEFINESHAPE4 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINESHAPE4);

  _iprintf (" CharacterID: %d\n", sblock->ShapeID);
  outputSWF_RECT (&(sblock->ShapeBounds));
  outputSWF_RECT (&(sblock->EdgeBounds));
  _iprintf("   UsesNonScalingStrokes: %d\n", sblock->UsesNonScalingStrokes);
  _iprintf("   UsesScalingStrokes: %d\n", sblock->UsesScalingStrokes);
  outputSWF_SHAPEWITHSTYLE (&(sblock->Shapes),2,"");
}

void
outputSWF_DEFINESOUND (SWF_Parserstruct * pblock)
{
	OUT_BEGIN (SWF_DEFINESOUND);
	_iprintf(" CharacterID: %d\n", sblock->SoundId);
	
	_iprintf(" SoundFormat: ");
	switch(sblock->SoundFormat)
	{
		case 0:	_iprintf("uncompressed\n"); break;
		case 1: _iprintf("ADPCM\n"); break;
		case 2: _iprintf("MP3\n"); break;
		case 3: _iprintf("uncompressed (LE)\n"); break;
		case 6: _iprintf("Nellymoser\n"); break;
		default: _iprintf("unknow ID %d\n", sblock->SoundFormat);
	}
	
	_iprintf(" SoundRate: ");
	switch(sblock->SoundRate)
	{
		case 0: _iprintf("5.5 KHz\n"); break;
		case 1: _iprintf("11 KHz\n"); break;
		case 2: _iprintf("22 KHz\n"); break;
		case 3: _iprintf("44 KHz\n"); break;
	}
	_iprintf(" SoundSize: %s\n", sblock->SoundSize?"16-bit":"8-bit");
	_iprintf(" SoundType: %s\n", sblock->SoundType?"Stereo":"Mono");
	_iprintf(" SoundSampleCount: %d\n", sblock->SoundSampleCount);

	if(sblock->SoundFormat == 2)
	{
		_iprintf("  Mp3: SeekSamples %i\n", 
			sblock->SoundData.mp3.SeekSamples);
	}
}

void
outputSWF_DEFINESPRITE (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_DEFINESPRITE);

  _iprintf(" CharacterID: %d\n", sblock->SpriteId );
  _iprintf(" FrameCount: %d\n", sblock->FrameCount );
  _iprintf(" BlockCount: %d\n", sblock->BlockCount );
  ++INDENT;
  for(i=0;i<sblock->BlockCount;i++) {
       outputBlock(sblock->tagTypes[i], sblock->Tags[i], NULL);
  }
  --INDENT;

}

void
outputSWF_DEFINETEXT (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_DEFINETEXT);

  _iprintf(" CharacterID: %d\n", sblock->CharacterID );
  outputSWF_RECT( &sblock->TextBounds );
  outputSWF_MATRIX( &sblock->TextMatrix, "" );
  _iprintf(" GlyphBits: %d\n", sblock->GlyphBits );
  _iprintf(" AdvanceBits: %d\n", sblock->AdvanceBits );
  _iprintf(" TextRecords: %d\n", sblock->numTextRecords );
  for(i=0;i<sblock->numTextRecords;i++) {
	  outputSWF_TEXTRECORD(&(sblock->TextRecords[i]), 1 );
  }

}

void
outputSWF_DEFINETEXT2 (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_DEFINETEXT2);

  _iprintf(" CharacterID: %d\n", sblock->CharacterID );
  outputSWF_RECT( &sblock->TextBounds );
  outputSWF_MATRIX( &sblock->TextMatrix, "" );
  _iprintf(" GlyphBits: %d\n", sblock->GlyphBits );
  _iprintf(" AdvanceBits: %d\n", sblock->AdvanceBits );
  _iprintf(" TextRecords: %d\n", sblock->numTextRecords );
  for(i=0;i<sblock->numTextRecords;i++) {
	  outputSWF_TEXTRECORD(&(sblock->TextRecords[i]), 2 );
  }
}

void
outputSWF_DEFINETEXTFORMAT (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_DEFINETEXTFORMAT);

}

void
outputSWF_DEFINEVIDEO (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_DEFINEVIDEO);

}

void
outputSWF_DEFINEVIDEOSTREAM (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINEVIDEOSTREAM);
  _iprintf("  CharacterID: %d\n", sblock->CharacterID);
  _iprintf("  NumFrames: %d\n", sblock->NumFrames);
  _iprintf("  Width: %d; Height %d\n", sblock->Width, sblock->Height);
  _iprintf("  Flag deblocking: %x\n", sblock->VideoFlagsDeblocking);
  _iprintf("  Flag smoothing: %x\n", sblock->VideoFlagsSmoothing);
  _iprintf("  Codec ID: %d\n", sblock->CodecID);
}

void
outputSWF_DOACTION (SWF_Parserstruct * pblock)
{
#ifdef NODECOMPILE
	int i;
#endif
	OUT_BEGIN (SWF_DOACTION);

#ifdef NODECOMPILE
	_iprintf(" %d Actions\n", sblock->numActions);
	for(i=0;i<sblock->numActions;i++)
	outputSWF_ACTION(i,&(sblock->Actions[i]));
#else
	_iprintf ("%s\n", decompile5Action(sblock->numActions, sblock->Actions, 0));
#endif

}

void
outputSWF_ENABLEDEBUGGER (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_ENABLEDEBUGGER);
  _iprintf(" Password: %s\n", sblock->Password);
}

void
outputSWF_ENABLEDEBUGGER2 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_ENABLEDEBUGGER2);
  _iprintf(" Password: %s\n", sblock->Password);
}


void
outputSWF_END (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_END);

}

void
outputSWF_EXPORTASSETS (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_EXPORTASSETS);

  _iprintf (" num assets: %d\n", sblock->Count );
  for (i = 0; i < sblock->Count; i++)
    {
	_iprintf (" Asset[%3.3d]: %s\n", sblock->Tags[i],
		  sblock->Names[i]);
    }

}

void
outputSWF_FONTREF (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_FONTREF);

}

void
outputSWF_FRAMELABEL (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_FRAMELABEL);

  _iprintf (" Name: %s\n", sblock->Name );
  _iprintf (" IsAnchor: %d\n", sblock->IsAnchor );
}

void
outputSWF_FRAMETAG (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_FRAMETAG);

}

void
outputSWF_FREEALL (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_FREEALL);

}

void
outputSWF_FREECHARACTER (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_FREECHARACTER);

}

void
outputSWF_GENCOMMAND (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_GENCOMMAND);

}

void
outputSWF_IMPORTASSETS (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_IMPORTASSETS);

  _iprintf (" URL: %s\n", sblock->URL );
  _iprintf (" num assets: %d\n", sblock->Count );
  for (i = 0; i < sblock->Count; i++)
    {
	_iprintf (" Asset[%3.3d]: %s\n", sblock->Tags[i],
		  sblock->Names[i]);
    }

}

void
outputSWF_IMPORTASSETS2 (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_IMPORTASSETS2);

  _iprintf (" URL: %s\n", sblock->URL );
  _iprintf (" num assets: %d\n", sblock->Count );
  for (i = 0; i < sblock->Count; i++)
    {
	_iprintf (" Asset[%3.3d]: %s\n", sblock->Tags[i],
		  sblock->Names[i]);
    }

}

void
outputSWF_JPEGTABLES (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_JPEGTABLES);

}

void
outputSWF_NAMECHARACTER (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_NAMECHARACTER);
  _iprintf("  Id: %d\n", sblock->Id);
  _iprintf("  Name: %s\n", sblock->Name);
}

void
outputSWF_PATHSAREPOSTSCRIPT (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_PATHSAREPOSTSCRIPT);

}

void
outputSWF_PLACEOBJECT (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_PLACEOBJECT);

}

void
outputSWF_PLACEOBJECT2 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_PLACEOBJECT2);

#if !defined(ACTIONONLY)
  _iprintf(" PlaceFlagHasClipActions %d\n", sblock->PlaceFlagHasClipActions);
  _iprintf(" PlaceFlagHasClipDepth %d\n", sblock->PlaceFlagHasClipDepth);
  _iprintf(" PlaceFlagHasName %d\n", sblock->PlaceFlagHasName);
  _iprintf(" PlaceFlagHasRatio %d\n", sblock->PlaceFlagHasRatio);
  _iprintf(" PlaceFlagHasColorTransform %d\n", sblock->PlaceFlagHasColorTransform);
  _iprintf(" PlaceFlagHasMatrix %d\n", sblock->PlaceFlagHasMatrix);
  _iprintf(" PlaceFlagHasCharacter %d\n", sblock->PlaceFlagHasCharacter);
  _iprintf(" PlaceFlagMove %d\n", sblock->PlaceFlagMove);
  _iprintf(" Depth %d\n", sblock->Depth);
  if( sblock->PlaceFlagHasCharacter )
	  _iprintf( " CharacterID: %d\n", sblock->CharacterId );
  if( sblock->PlaceFlagHasMatrix )
	outputSWF_MATRIX (&(sblock->Matrix), "");
  if( sblock->PlaceFlagHasColorTransform )
	outputSWF_CXFORMWITHALPHA (&(sblock->ColorTransform), "");
  if( sblock->PlaceFlagHasRatio )
	  _iprintf( " Ratio: %d\n", sblock->Ratio );
  if( sblock->PlaceFlagHasName )
	  _iprintf( " Name: %s\n", sblock->Name );
  if( sblock->PlaceFlagHasClipDepth )
	  _iprintf( " ClipDepth: %d\n", sblock->ClipDepth );
#endif
  if( sblock->PlaceFlagHasClipActions )
	outputSWF_CLIPACTIONS (&(sblock->ClipActions));
}

void
outputSWF_PLACEOBJECT3 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_PLACEOBJECT3);
#if !defined(ACTIONONLY)
  _iprintf(" PlaceFlagHasClipActions %d\n", sblock->PlaceFlagHasClipActions);
  _iprintf(" PlaceFlagHasClipDepth %d\n", sblock->PlaceFlagHasClipDepth);
  _iprintf(" PlaceFlagHasName %d\n", sblock->PlaceFlagHasName);
  _iprintf(" PlaceFlagHasRatio %d\n", sblock->PlaceFlagHasRatio);
  _iprintf(" PlaceFlagHasColorTransform %d\n", sblock->PlaceFlagHasColorTransform);
  _iprintf(" PlaceFlagHasMatrix %d\n", sblock->PlaceFlagHasMatrix);
  _iprintf(" PlaceFlagHasCharacter %d\n", sblock->PlaceFlagHasCharacter);
  _iprintf(" PlaceFlagMove %d\n", sblock->PlaceFlagMove);
  _iprintf(" PlaceFlagHasImage %d\n", sblock->PlaceFlagHasImage);
  _iprintf(" PlaceFlagHasClassName %d\n", sblock->PlaceFlagHasClassName);
  _iprintf(" PlaceFlagHasCacheAsbitmap %d\n", sblock->PlaceFlagHasCacheAsBitmap);
  _iprintf(" PlaceFlagHasBlendMode %d\n", sblock->PlaceFlagHasBlendMode);
  _iprintf(" PlaceFlagHasFilterList %d\n", sblock->PlaceFlagHasFilterList); 
  _iprintf(" Depth %d\n", sblock->Depth);
 
  if( sblock->PlaceFlagHasClassName ||
      (sblock->PlaceFlagHasImage && sblock->PlaceFlagHasCharacter))
    _iprintf(" ClassName %s\n", sblock->ClassName);
  
  if( sblock->PlaceFlagHasCharacter )
	  _iprintf( " CharacterID: %d\n", sblock->CharacterId );
  if( sblock->PlaceFlagHasMatrix )
	outputSWF_MATRIX (&(sblock->Matrix), "");
  if( sblock->PlaceFlagHasColorTransform )
	outputSWF_CXFORMWITHALPHA (&(sblock->ColorTransform), "");
  if( sblock->PlaceFlagHasRatio )
	  _iprintf( " Ratio: %d\n", sblock->Ratio );
  if( sblock->PlaceFlagHasName )
	  _iprintf( " Name: %s\n", sblock->Name );
  if( sblock->PlaceFlagHasClipDepth )
	  _iprintf( " ClipDepth: %d\n", sblock->ClipDepth );
  if( sblock->PlaceFlagHasBlendMode )
	  _iprintf("  BlendMode %d\n", sblock->BlendMode );
  if( sblock->PlaceFlagHasFilterList )
  {
	  int i;
	  SWF_FILTERLIST *filterList = &sblock->SurfaceFilterList;
	  
	  _iprintf("  NumberOfFilters %d\n", filterList->NumberOfFilters);
	  
	  for(i = 0; i < filterList->NumberOfFilters; i++)
	    outputSWF_FILTER(filterList->Filter + i);
  }
#endif
  if( sblock->PlaceFlagHasClipActions )
	outputSWF_CLIPACTIONS (&(sblock->ClipActions));

}

void
outputSWF_PREBUILT (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_PREBUILT);

}

void
outputSWF_PREBUILTCLIP (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_PREBUILTCLIP);

}

void
outputSWF_PROTECT (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_PROTECT);

  if( sblock->Password )
    _iprintf(" Password: %s\n", sblock->Password);

}

void
outputSWF_REMOVEOBJECT (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_REMOVEOBJECT);

  _iprintf(" CharacterID: %d\n", sblock->CharacterId);
  _iprintf(" Depth: %d\n", sblock->Depth);

}

void
outputSWF_REMOVEOBJECT2 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_REMOVEOBJECT2);
  _iprintf(" Depth: %d\n", sblock->Depth);

}

void
outputSWF_SERIALNUMBER (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_SERIALNUMBER);
  _iprintf("Version %d.%d.%d.%d\n", sblock->Id, sblock->Edition, 
	sblock->Major, sblock->Minor);
  _iprintf("Build: %lu\n", (((long long)sblock->BuildH) << 32) + sblock->BuildL);
  _iprintf("Timestamp: %lu\n", 
	(((long long)sblock->TimestampH) << 32) + sblock->TimestampL);
}

void
outputSWF_SETBACKGROUNDCOLOR (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_SETBACKGROUNDCOLOR);

  outputSWF_RGBA (&sblock->rgb, "");

}

void
outputSWF_SHOWFRAME (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_SHOWFRAME);

}


void
outputSWF_SOUNDSTREAMBLOCK (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_SOUNDSTREAMBLOCK);
  if(m.soundStreamFmt == 2)
  {
    _iprintf("  SampleCount %u\n", sblock->StreamData.mp3.SampleCount);
    _iprintf("  Mp3: SeekSamples %i\n", 
           sblock->StreamData.mp3.SeekSamples);
  }
}

void
outputSWF_SOUNDSTREAMHEAD (SWF_Parserstruct * pblock)
{
  char *tmp;

  OUT_BEGIN (SWF_SOUNDSTREAMHEAD);
  switch(sblock->PlaybackSoundRate)
  {
    case 0: tmp = "5.5 kHz"; break;
    case 1: tmp = "11 kHz"; break;
    case 2: tmp = "22 kHz"; break;
    case 3: tmp = "44 kHz"; break;
    default: tmp = "error";
  }
  _iprintf("  PlaybackSoundRate %s\n", tmp);

  switch(sblock->PlaybackSoundSize)
  {
    case 1: tmp = "16 bit"; break;
    default: tmp = "error";
  }
  _iprintf("  PlaybackSoundSize %s\n", tmp);

  switch(sblock->PlaybackSoundType)
  {
    case 0: tmp = "mono"; break;
    case 1: tmp = "stereo"; break;
    default: tmp = "error";
  }
  _iprintf("  PlaybackSoundType %s\n", tmp);

  switch(sblock->StreamSoundCompression)
  {
    case 1: tmp = "ADPCM"; break;
    case 2: tmp = "MP3"; break;
    default: tmp ="error";
  }
  _iprintf("  StreamSoundCompression %s\n", tmp);

  switch(sblock->StreamSoundRate)
  {
    case 0: tmp = "5.5 kHz"; break;
    case 1: tmp = "11 kHz"; break;
    case 2: tmp = "22 kHz"; break;
    case 3: tmp = "44 kHz"; break;
    default: tmp = "error";
  }
  _iprintf("  StreamSoundRate %s\n", tmp);

  switch(sblock->StreamSoundSize)
  {
    case 1: tmp = "16 bit"; break;
    default: tmp = "error";
  }
  _iprintf("  StreamSoundSize %s\n", tmp);

  switch(sblock->StreamSoundType)
  {
    case 0: tmp = "mono"; break;
    case 1: tmp = "stereo"; break;
    default: tmp = "error";
  }
  _iprintf("  StreamSoundType %s\n", tmp);
  _iprintf("  StreamSoundSampleCount %u\n", sblock->StreamSoundSampleCount);
  if(sblock->StreamSoundCompression == 2)
    _iprintf("  LatencySeek %i\n", sblock->LatencySeek);  
}

void
outputSWF_SOUNDSTREAMHEAD2 (SWF_Parserstruct * pblock)
{
  char *tmp;
  OUT_BEGIN (SWF_SOUNDSTREAMHEAD2);
  switch(sblock->PlaybackSoundRate)
  {
    case 0: tmp = "5.5 kHz"; break;
    case 1: tmp = "11 kHz"; break;
    case 2: tmp = "22 kHz"; break;
    case 3: tmp = "44 kHz"; break;
    default: tmp = "error";
  }
  _iprintf("  PlaybackSoundRate %s\n", tmp);

  switch(sblock->PlaybackSoundSize)
  {
    case 0: tmp = "8 bit"; break;
    case 1: tmp = "16 bit"; break;
    default: tmp = "error";
  }
  _iprintf("  PlaybackSoundSize %s\n", tmp);

  switch(sblock->PlaybackSoundType)
  {
    case 0: tmp = "mono"; break;
    case 1: tmp = "stereo"; break;
    default: tmp = "error";
  }
  _iprintf("  PlaybackSoundType %s\n", tmp);

  switch(sblock->StreamSoundCompression)
  {
    case 0: tmp = "uncompressed"; break;
    case 1: tmp = "ADPCM"; break;
    case 2: tmp = "MP3"; break;
    case 3: tmp = "uncompressed"; break;
    case 6: tmp = "Nellymoser"; break;
    default: tmp ="error";
  }
  _iprintf("  StreamSoundCompression %s\n", tmp);

  switch(sblock->StreamSoundRate)
  {
    case 0: tmp = "5.5 kHz"; break;
    case 1: tmp = "11 kHz"; break;
    case 2: tmp = "22 kHz"; break;
    case 3: tmp = "44 kHz"; break;
    default: tmp = "error";
  }
  _iprintf("  StreamSoundRate %s\n", tmp);

  switch(sblock->StreamSoundSize)
  {
    case 0: tmp = "8 bit"; break;
    case 1: tmp = "16 bit"; break;
    default: tmp = "error";
  }
  _iprintf("  StreamSoundSize %s\n", tmp);

  switch(sblock->StreamSoundType)
  {
    case 0: tmp = "mono"; break;
    case 1: tmp = "stereo"; break;
    default: tmp = "error";
  }
  _iprintf("  StreamSoundType %s\n", tmp);
  _iprintf("  StreamSoundSampleCount %u\n", sblock->StreamSoundSampleCount);
  if(sblock->StreamSoundCompression == 2)
    _iprintf("  LatencySeek %i\n", sblock->LatencySeek);
}

void
outputSWF_SOUNDENVELOPE (SWF_SOUNDENVELOPE *env)
{
  _iprintf("    SoundEnvelope:");
  _iprintf(" Pos44 %d, LeftLevel %d, RightLevel %d\n",
    env->Pos44, env->LeftLevel, env->RightLevel);
}

void 
outputSWF_SOUNDINFO (SWF_SOUNDINFO *info)
{
  _iprintf("  SoundInfo:\n");
  _iprintf("    SyncStop: %s\n", info->SyncStop?"Yes":"No");
  _iprintf("    SyncNoMultiple: %s\n", info->SyncNoMultiple?"Yes":"No");
  _iprintf("    HasEnvelope: %s\n", info->HasEnvelope?"Yes":"No");
  _iprintf("    Loops: %d\n", info->HasLoops?info->LoopCount:0);
  
  if(info->HasOutPoint)
    _iprintf(" HasOutPoint: %d", info->OutPoint);

  if(info->HasInPoint)
    _iprintf(" HasInPoint: %d", info->InPoint);

  _iprintf("\n");

  if(info->HasEnvelope)
  {
    int i;
    _iprintf("    EnvPoints %d\n", info->EnvPoints);
    for(i = 0; i < info->EnvPoints; i++)
      outputSWF_SOUNDENVELOPE(info->EnvelopeRecords + i);
  }
} 

void
outputSWF_STARTSOUND (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_STARTSOUND);
  _iprintf(" SoundId %d\n", sblock->SoundId);
  outputSWF_SOUNDINFO(&sblock->SoundInfo);
}

void
outputSWF_STARTSOUND2 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_STARTSOUND2);
  _iprintf(" SoundClassName %s\n", sblock->SoundClassName);
  outputSWF_SOUNDINFO(&sblock->SoundInfo);
}

void
outputSWF_SYNCFRAME (SWF_Parserstruct * pblock)
{
  //OUT_BEGIN (SWF_SYNCFRAME);

}

void
outputSWF_INITACTION (SWF_Parserstruct * pblock)
{
#ifdef NODECOMPILE
	int i;
#endif
	OUT_BEGIN (SWF_INITACTION);

	_iprintf(" %d Init actions for character %u\n", sblock->numActions, sblock->SpriteId);
#ifdef NODECOMPILE
	for(i=0;i<sblock->numActions;i++)
		outputSWF_ACTION(i,&(sblock->Actions[i]));
#else
	_iprintf ("%s\n", decompile5Action(sblock->numActions,sblock->Actions,0));
#endif

}
void
outputSWF_VIDEOFRAME (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_VIDEOFRAME);
  _iprintf("  StreamID %i\n", sblock->StreamID);
  _iprintf("  FrameNum %i\n", sblock->FrameNum);
}

void
outputSWF_REFLEX (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_REFLEX);

  _iprintf(" Reflex: \"%c%c%c\"\n", sblock->rfx[0], sblock->rfx[1], sblock->rfx[2]);
}

void 
outputSWF_FILEATTRIBUTES(SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_FILEATTRIBUTES);
  
  _iprintf(" FileAttributes: HasMetaData %d, UseNetwork %d, HasAS3 %d\n", 
          sblock->HasMetadata, sblock->UseNetwork, sblock->ActionScript3);
}

void 
outputSWF_METADATA(SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_METADATA);
  
  _iprintf(" Metadata: \n%s\n\n", 
          sblock->Metadata);
}

void 
outputSWF_SCRIPTLIMITS(SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_SCRIPTLIMITS);
  _iprintf(" MaxRecursionDepth %d\n", sblock->MaxRecursionDepth);
  _iprintf(" ScriptTimeoutSeconds %d\n", sblock->ScriptTimeoutSeconds);
}

void 
outputSWF_DEFINESCALINGGRID(SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DEFINESCALINGGRID);
  _iprintf(" CharacterId %d\n", sblock->CharacterId);
  outputSWF_RECT(&sblock->Splitter);
}

void 
outputSWF_SETTABINDEX(SWF_Parserstruct *pblock)
{
  OUT_BEGIN (SWF_SETTABINDEX);
  _iprintf(" Depth: %d\n", sblock->Depth);
  _iprintf(" TabIndex: %d\n", sblock->TabIndex);
}

static void 
outputNSSetConstant(struct ABC_FILE *abc, unsigned int index);
static void 
outputNamespaceConstant(struct ABC_FILE *abc, unsigned int index);
static void 
outputMultinameConstant(struct ABC_FILE *abc, unsigned int index);
static void 
outputStringConstant(struct ABC_FILE *abc, unsigned int strIndex);

static void 
outputABC_STRING_INFO(struct ABC_STRING_INFO *si)
{
  char *buffer, *bufp;
  int i;
  if(si->Size == 0)
  {
    _iprintf("     ** empty ** (0)\n");
    return;
  }

  // we don't deal with utf8 yet
  buffer = malloc(si->Size+1);
  memset(buffer, 0, si->Size+1);
  bufp = buffer;
  for(i = 0; i < si->Size; i++)
  {
    if(si->UTF8String[i] < 128)
      *bufp++ = si->UTF8String[i];
  }
  _iprintf("   '%s' (%i)\n", buffer, si->Size);
  free(buffer);

}

static void 
outputABC_QNAME(struct ABC_FILE *abc, struct ABC_QNAME *qn)
{
  outputNamespaceConstant(abc, qn->NS);
  outputStringConstant(abc, qn->Name);
}

static void 
outputABC_RTQNAME(struct ABC_FILE *abc, struct ABC_RTQNAME *rtq)
{
  outputStringConstant(abc, rtq->Name);
}

static void
outputABC_MULTINAME(struct ABC_FILE *abc, struct ABC_MULTINAME *mn)
{
  outputStringConstant(abc, mn->Name);
  outputNSSetConstant(abc, mn->NSSet);
}

static void
outputABC_MULTINAME_L(struct ABC_FILE *abc, struct ABC_MULTINAME_L *ml)
{
  outputNSSetConstant(abc, ml->NSSet);
}

static void outputABC_MULTINAME_INFO(struct ABC_FILE *abc, 
                                     struct ABC_MULTINAME_INFO *mi)
{
  switch(mi->Kind)
  {
    case ABC_CONST_QNAME:
    case ABC_CONST_QNAME_A:
      _iprintf("    Multiname ABC_CONST_QNAME(A)");
      outputABC_QNAME(abc, &mi->Data.QName);
      break; 
    case ABC_CONST_RTQNAME:
    case ABC_CONST_RTQNAME_A:
      _iprintf("    Multiname ABC_CONST_RTQNAME(A)");
      outputABC_RTQNAME(abc, &mi->Data.RTQName); 
      break;
    case ABC_CONST_RTQNAME_L:
    case ABC_CONST_RTQNAME_LA:
      _iprintf("    Multiname ABC_CONST_MULTINAME(A)");
      break;
    case ABC_CONST_MULTINAME:
    case ABC_CONST_MULTINAME_A:
      _iprintf("    Multiname ABC_CONST_MULTINAME(A)");
      outputABC_MULTINAME(abc, &mi->Data.Multiname); 
      break;
    case ABC_CONST_MULTINAME_L:
    case ABC_CONST_MULTINAME_LA:
      _iprintf("    Multiname ABC_CONST_MULTINAME(A)");
      outputABC_MULTINAME_L(abc, &mi->Data.MultinameL); 
      break;
   }
}

static void 
outputABC_NS_INFO(struct ABC_FILE *abc, struct ABC_NS_INFO *ns)
{
  _iprintf("    Namespace Kind %x\n", ns->Kind);
  outputStringConstant(abc, ns->Name);
}

static void 
outputABC_NS_SET_INFO(struct ABC_FILE *abc, struct ABC_NS_SET_INFO *set)
{
  int i;
  for(i = 0; i < set->Count; i++)
  {
    unsigned int index = set->NS[i];
    outputNamespaceConstant(abc, index);
  }
}

static void 
outputNSSetConstant(struct ABC_FILE *abc, unsigned int index)
{
  struct ABC_CONSTANT_POOL *cp = &abc->ConstantPool;
  if(index >= cp->NamespaceSetCount)
  {
    _iprintf("ConstantPool NamespaceSetCount %u <= index %u\n",
      cp->NamespaceSetCount, index);
    return;
  }

  if(index == 0)
  {
    _iprintf("*\n");
    return;
  }
  outputABC_NS_SET_INFO(abc, cp->NsSets + index);
}


static void 
outputNamespaceConstant(struct ABC_FILE *abc, unsigned int index)
{
  struct ABC_CONSTANT_POOL *cp = &abc->ConstantPool;
  if(index >= cp->NamespaceCount)
  {
    _iprintf("ConstantPool NamespaceCount %u <= index %u\n",
      cp->NamespaceCount, index);
    return;
  }

  if(index == 0)
  {
    _iprintf("*\n");
    return;
  }
  outputABC_NS_INFO(abc, cp->Namespaces + index);
}

static void 
outputMultinameConstant(struct ABC_FILE *abc, unsigned int index)
{
  struct ABC_CONSTANT_POOL *cp = &abc->ConstantPool;
  if(index >= cp->MultinameCount)
  {
    _iprintf("ConstantPool MultinameCount %u <= index %u\n",
      cp->MultinameCount, index);
    return;
  }

  if(index == 0)
  {
    _iprintf("Multiname index 0 is not allowed\n");
    return;
  }
  outputABC_MULTINAME_INFO(abc, cp->Multinames + index);
}

static void 
outputIntConstant(struct ABC_FILE *abc, unsigned int index)
{
  struct ABC_CONSTANT_POOL *cp = &abc->ConstantPool;
  if(index >= cp->IntCount)
  {
    _iprintf("ConstantPool IntCount %u <= index %u\n",
      cp->IntCount, index);
    return;
  }

  if(index == 0)
  {
    _iprintf("Integer index 0 is not allowed\n");
    return;
  }
  _iprintf("Int %i\n", cp->Integers[index]);
}

static void 
outputUIntConstant(struct ABC_FILE *abc, unsigned int index)
{
  struct ABC_CONSTANT_POOL *cp = &abc->ConstantPool;
  if(index >= cp->UIntCount)
  {
    _iprintf("ConstantPool UIntCount %u <= index %u\n",
      cp->UIntCount, index);
    return;
  }

  if(index == 0)
  {
    _iprintf("UInteger index 0 is not allowed\n");
    return;
  }
  _iprintf("    UInt %u\n", cp->UIntegers[index]);
}

static void 
outputDoubleConstant(struct ABC_FILE *abc, unsigned int index)
{
  struct ABC_CONSTANT_POOL *cp = &abc->ConstantPool;
  if(index >= cp->DoubleCount)
  {
    _iprintf("ConstantPool DoubleCount %u <= index %u\n",
      cp->DoubleCount, index);
    return;
  }

  if(index == 0)
  {
    _iprintf("    NaN\n");
    return;
  }
  _iprintf("    Double %f\n", cp->Doubles[index]);
}


static void 
outputStringConstant(struct ABC_FILE *abc, unsigned int strIndex)
{
  struct ABC_CONSTANT_POOL *cp = &abc->ConstantPool;
  if(strIndex >= cp->StringCount)
  {
    _iprintf("ConstantPool StringCount %u <= strIndex %u\n",
      cp->StringCount, strIndex);
    return;
  }

  if(strIndex == 0)
  {
    _iprintf("    *\n");
    return;
  }
  outputABC_STRING_INFO(cp->Strings + strIndex);
}

void outputABC_OPTION_INFO(struct ABC_FILE *abc, struct ABC_OPTION_INFO *o)
{
  int i;
  for (i = 0; i < o->OptionCount; i++)
  {
    unsigned int index = o->Option[i].Val;
    _iprintf("   Option: ");
    switch(o->Option[i].Kind)
    {
      case ABC_INT:
        outputIntConstant(abc, index);
        break;
      case ABC_UINT:
        outputUIntConstant(abc, index);
        break;
      case ABC_DOUBLE:
        outputDoubleConstant(abc, index);
        break;
      case ABC_UTF8:
        outputStringConstant(abc, index);
        break;
      case ABC_TRUE:
        _iprintf(" TRUE\n");
        break;
      case ABC_FALSE:
        _iprintf(" FALSE\n");
        break;
      case ABC_NULL:
        _iprintf(" NULL\n");
        break;
      case ABC_UNDEF:
        _iprintf(" UNDEF\n");
        break;
      case ABC_NAMESPACE:
      case ABC_PACKAGE_NS:
      case ABC_PACKAGE_INTERNAL_NS:
      case ABC_PROTECTED_NS:
      case ABC_EXPLICIT_NS:
      case ABC_STATIC_PROTECTED_NS:
      case ABC_PRIVATE_NS:
        outputNamespaceConstant(abc, index);
        break;
      default:
        _iprintf("Option type %x unknown\n", o->Option[i].Kind);
    }
  }
}

void outputABC_METHOD_INFO(struct ABC_FILE *abc, struct ABC_METHOD_INFO *minfo)
{
  int i;
  _iprintf("   ParamCount %u\n", minfo->ParamCount);
  _iprintf("   ReturnType \n   {\n");
  if(minfo->ReturnType)
    outputMultinameConstant(abc, minfo->ReturnType);
  else 
    _iprintf("    void\n");
  _iprintf("   }\n\n");
  for(i = 0; i < minfo->ParamCount; i++)
  {
    unsigned int index = minfo->ParamType[i];
    _iprintf("    Parameter %i\n    {\n", i);
    outputMultinameConstant(abc, index);
    _iprintf("    }\n");
  }

  _iprintf("   Name (%u) ",  minfo->Name);
  if(minfo->Name)
    outputStringConstant(abc, minfo->Name);
  else
    _iprintf("**no name**\n");

  _iprintf("   Flags %x\n", minfo->Flags);
  if(minfo->Flags & ABC_METHOD_HAS_OPTIONAL)
    outputABC_OPTION_INFO(abc, &minfo->Options);
  if(minfo->Flags & ABC_METHOD_HAS_PARAM_NAMES)
  {
    int i;
    _iprintf("    Parameter Names:\n");
    for(i = 0; i < minfo->ParamCount; i++)
    {
      int strIndex = minfo->ParamType[i];
      outputStringConstant(abc, strIndex);
    }
  }
}


void outputABC_CONSTANT_POOL(struct ABC_CONSTANT_POOL *cpool)
{
  _iprintf("  ConstantPool: \n");
  _iprintf("   Integers: %u, Unsigend %u Doubles %u\n", 
    cpool->IntCount, cpool->UIntCount, cpool->DoubleCount);
  _iprintf("   Strings %u, Namespaces %u, NS-Sets %u, Multinames %u\n\n",
    cpool->StringCount, cpool->NamespaceCount, cpool->NamespaceSetCount,
    cpool->MultinameCount); 
}

void 
outputABC_METADATA_INFO(struct ABC_FILE *abc, struct ABC_METADATA_INFO *mi)
{
  unsigned int i;

  _iprintf("    Name: ");
  outputStringConstant(abc, mi->Name);

  for(i = 0; i < mi->ItemCount; i++)
  {
    _iprintf("    Key (%u) ", mi->Items[i].Key);
    outputStringConstant(abc, mi->Items[i].Key);
    _iprintf("    Value (%u) ", mi->Items[i].Value);
    outputStringConstant(abc, mi->Items[i].Value);
    _iprintf("\n");
  }
}

void 
outputABC_TRAIT_SLOT(struct ABC_FILE *abc, struct ABC_TRAIT_SLOT *ts)
{
  _iprintf("   Trait Slot\n");
  _iprintf("    SlotId %u\n", ts->SlotId);
  _iprintf("    Type Name ");
  if(ts->TypeName)
    outputMultinameConstant(abc, ts->TypeName);
  else
    _iprintf(" * ");
  _iprintf("\n");
  
  _iprintf("    VIndex %u\n", ts->VIndex);
  if(ts->VIndex)
    _iprintf("    VKind %u\n", ts->VKind);
}

void
outputABC_TRAIT_CLASS(struct ABC_FILE *abc, struct ABC_TRAIT_CLASS *tc)
{
  _iprintf("   Trait Class\n");
  _iprintf("    SlotId %u\n", tc->SlotId);
  _iprintf("    Class Index %u\n", tc->ClassIndex);
}

void
outputABC_TRAIT_FUNCTION(struct ABC_FILE *abc, struct ABC_TRAIT_FUNCTION *tf)
{
  _iprintf("   Trait Function\n");
  _iprintf("    SlotId %u\n", tf->SlotId);
  _iprintf("    Method Index %u\n", tf->Function);
}

void
outputABC_TRAIT_METHOD(struct ABC_FILE *abc, struct ABC_TRAIT_METHOD *tm)
{
  _iprintf("   Trait Method\n");
  _iprintf("    DispId %u\n", tm->DispId);
  _iprintf("    Method Index %u\n", tm->Method);
}


void 
outputABC_TRAITS_INFO(struct ABC_FILE *abc, struct ABC_TRAITS_INFO *ti)
{
  _iprintf("    Name: ");
  outputMultinameConstant(abc, ti->Name);
  _iprintf("\n");
  
  switch(ti->Kind & 0xf)
  {
    case ABC_CONST_TRAIT_SLOT:
    case ABC_CONST_TRAIT_CONST:
      outputABC_TRAIT_SLOT(abc, &ti->Data.Slot);
      break;
    case ABC_CONST_TRAIT_CLASS:
      outputABC_TRAIT_CLASS(abc, &ti->Data.Class);
      break;
    case ABC_CONST_TRAIT_FUNCTION:
      outputABC_TRAIT_FUNCTION(abc, &ti->Data.Function);
      break;
    case ABC_CONST_TRAIT_METHOD:
    case ABC_CONST_TRAIT_GETTER:
    case ABC_CONST_TRAIT_SETTER:
      outputABC_TRAIT_METHOD(abc, &ti->Data.Method);
      break;
    default:
      _iprintf("unknown trait %x\n", ti->Kind);
  }
  
  _iprintf("    Trait Attr %x\n", ti->Attr);
  if(ti->Attr & ABC_TRAIT_ATTR_METADATA)
  {
    unsigned int i;
    _iprintf("    Trait Metadata Num %u\n", ti->MetadataCount);
    for(i = 0; i < ti->MetadataCount; i++)
    {
      _iprintf("     Metadata[%u] -> %u\n", i, ti->Metadata[i]);
    }
  }
}

void 
outputABC_INSTANCE_INFO(struct ABC_FILE *abc, struct ABC_INSTANCE_INFO *ii)
{
  unsigned int i; 

  _iprintf("    Name: ");
  outputStringConstant(abc, ii->Name);
  _iprintf("    SuperName: ");
  outputStringConstant(abc, ii->SuperName);
  _iprintf("    Flags %x\n", ii->Flags);
  
  if(ii->Flags & ABC_CLASS_PROTECTED_NS)
  { 
    _iprintf("    Protected NS ");
    outputNamespaceConstant(abc, ii->ProtectedNs);
  }
  
  _iprintf("    Interfaces: (%u)\n", ii->InterfaceCount);
  for(i = 0; i < ii->InterfaceCount; i++)
  {
    _iprintf("    Interface (%u)", i);
    outputMultinameConstant(abc, ii->Interfaces[i]);
  }
  _iprintf("    Init Method #%u\n", ii->IInit);

  _iprintf("    Traits (%u):\n", ii->TraitCount);
  for(i = 0; i < ii->TraitCount; i++)
  {
    _iprintf("    Trait %u:\n", i);
    outputABC_TRAITS_INFO(abc, ii->Traits + i);
  }
}

void 
outputABC_CLASS_INFO(struct ABC_FILE *abc, struct ABC_CLASS_INFO *ci)
{
  unsigned int i;

  _iprintf("    Init Method #%u\n", ci->CInit);

  _iprintf("    Traits (%u):\n", ci->TraitCount);
  for(i = 0; i < ci->TraitCount; i++)
  {
    _iprintf("    Trait %u:\n", i);
    outputABC_TRAITS_INFO(abc, ci->Traits + i);
  }
}

void 
outputABC_SCRIPT_INFO(struct ABC_FILE *abc, struct ABC_SCRIPT_INFO *si)
{
  unsigned int i;

  _iprintf("    Init Method #%u\n", si->Init);

  _iprintf("    Traits (%u):\n", si->TraitCount);
  for(i = 0; i < si->TraitCount; i++)
  {
    _iprintf("    Trait %u:\n", i);
    outputABC_TRAITS_INFO(abc, si->Traits + i);
  }
}

void
outputABC_EXCEPTION_INFO(struct ABC_FILE *abc, struct ABC_EXCEPTION_INFO *ei)
{
  _iprintf("    From: %u\n", ei->From);
  _iprintf("    To: %u\n", ei->To);
  _iprintf("    Target: %u\n", ei->Target);
  _iprintf("    ExcType: ");
  outputStringConstant(abc, ei->ExcType);
  _iprintf("    VarName: ");
  outputStringConstant(abc, ei->VarName); 
}

void 
outputABC_METHOD_BODY_INFO(struct ABC_FILE *abc, struct ABC_METHOD_BODY_INFO *mb)
{
  unsigned int i;

  _iprintf("    Method Index -> %u\n", mb->Method);
  _iprintf("    Max Stack %u\n", mb->MaxStack);
  _iprintf("    LocalCount %u\n", mb->LocalCount);
  _iprintf("    InitScopeDepth %u\n", mb->InitScopeDepth);
  _iprintf("    MaxScopeDepth %u\n", mb->CodeLength);
  _iprintf("    CodeLength %u\n", mb->CodeLength);
  
  _iprintf("    ExceptionCount %u\n", mb->ExceptionCount);
  for(i = 0; i < mb->ExceptionCount; i++)
  {
    _iprintf("    Exception [%u]: \n", i);
    outputABC_EXCEPTION_INFO(abc, mb->Exceptions + i);
  }

  _iprintf("    Traits (%u):\n", mb->TraitCount);
  for(i = 0; i < mb->TraitCount; i++)
  {
    _iprintf("    Trait [%u]:\n", i);
    outputABC_TRAITS_INFO(abc, mb->Traits + i);
  }
}

void outputABC_FILE(struct ABC_FILE *abc)
{
  unsigned int i;

  _iprintf(" Version %i.%i\n", abc->Major, abc->Minor);
  outputABC_CONSTANT_POOL(&abc->ConstantPool);

  _iprintf(" MethodCount %u\n", abc->MethodCount);
  for(i = 0; i < abc->MethodCount; i++)
  {
    _iprintf("  Method Info[%u]:\n", i);
    outputABC_METHOD_INFO(abc, abc->Methods + i);
    _iprintf("  ### Method done ###\n\n");
  }
  _iprintf(" ### Method Info done ###\n\n");

  _iprintf(" MetadataCount %u\n", abc->MetadataCount);
  for(i = 0; i < abc->MetadataCount; i++)
  {
    _iprintf("  Metadata [%u]:\n", i);
    outputABC_METADATA_INFO(abc, abc->Metadata + i);
    _iprintf("  ### Metadata done ###\n\n");
  }
  _iprintf(" ### Metadata Info done ###\n\n");

  _iprintf(" InstanceCount %u\n", abc->ClassCount);
  for(i = 0; i < abc->ClassCount; i++)
  {
    _iprintf("  Instance [%u]:\n", i);
    outputABC_INSTANCE_INFO(abc, abc->Instances + i);
    _iprintf("  ### Instance done ###\n\n");
  }
  _iprintf(" ### Instances Info done ###\n\n");
  
  _iprintf(" ClassCount %u\n", abc->ClassCount);
  for(i = 0; i < abc->ClassCount; i++)
  {
    _iprintf("  Class [%u]:\n", i);
    outputABC_CLASS_INFO(abc, abc->Classes + i);
    _iprintf("  ### Class done ###\n\n");
  }
  _iprintf(" ### Class Info done ###\n\n");

  _iprintf(" ScriptCount %u\n", abc->ScriptCount);
  for(i = 0; i < abc->ScriptCount; i++)
  {
    _iprintf("  Script [%u]:\n", i);
    outputABC_SCRIPT_INFO(abc, abc->Scripts + i);
    _iprintf("  ### Script done ###\n\n");
  }
  _iprintf(" ### Script Info done ###\n\n");

  _iprintf(" MethodBodyCount %u\n", abc->MethodBodyCount);
  for(i = 0; i < abc->MethodBodyCount; i++)
  {
    _iprintf("  Method Body [%u]:\n", i);
    outputABC_METHOD_BODY_INFO(abc, abc->MethodBodies + i);
    _iprintf("  ### Method Body done ###\n\n");
  }
  _iprintf(" ### Method Body Info done ###\n\n"); 
}

void
outputSWF_DOABC(SWF_Parserstruct *pblock)
{
  OUT_BEGIN (SWF_DOABC);
  _iprintf(" ActionFlags: %x\n", sblock->Flags);
  _iprintf(" Name %s\n", sblock->Name);
  outputABC_FILE(&sblock->AbcFile);
}

void 
outputSWF_SYMBOLCLASS(SWF_Parserstruct *pblock)
{
  int count, i;
  OUT_BEGIN(SWF_SYMBOLCLASS);
  count = sblock->SymbolCount;
  _iprintf("SymbolCount %i\n", count);
  for(i = 0; i < count; i++)
  {
    _iprintf(" Id: %i, Name: %s\n", 
      sblock->SymbolList[i].SymbolId, sblock->SymbolList[i].SymbolName);
  }
}

void 
outputSWF_DEFINESCENEANDFRAMEDATA(SWF_Parserstruct *pblock)
{
  int i;
  OUT_BEGIN(SWF_DEFINESCENEANDFRAMEDATA);
  _iprintf(" SceneCount: %d\n", sblock->SceneCount);
  for(i = 0; i < sblock->SceneCount; i++)
    _iprintf("  Scene #%d: Offset: %d, Name: %s\n", 
	i, sblock->Scenes[i].Offset, sblock->Scenes[i].Name);

  _iprintf(" FrameLabelCount: %d\n", sblock->FrameLabelCount);
  for(i = 0; i < sblock->FrameLabelCount; i++)
    _iprintf("  FrameLabel #%d: Frame: %d, Name: %s\n", 
	i, sblock->Frames[i].FrameNum, sblock->Frames[i].FrameLabel);
}

void 
outputSWF_DEBUGID(SWF_Parserstruct *pblock)
{
  int i;
  OUT_BEGIN(SWF_DEBUGID);
  _iprintf(" UUID: ");
  for(i = 0; i < pblock->length; i++)
    _iprintf("%x ", sblock->UUID[i]);
  _iprintf("\n");
}

void 
outputSWF_UNKNOWNBLOCK(SWF_Parserstruct *pblock)
{
  OUT_BEGIN(SWF_UNKNOWNBLOCK);
  if(sblock->Data == NULL)
	return;
  dumpBuffer(sblock->Data, pblock->length);
}


void
printRect(struct Rect *r)
{
	_iprintf("(%i,%i)x(%i,%i)", r->xMin, r->xMax, r->yMin, r->yMax);
}

void
outputHeader (struct Movie *m)
{

	setNewLineString("\n");

	_iprintf("File version: %i\n", m->version);
	_iprintf("File size: %i\n", m->size);

	_iprintf("Frame size: ");
	printRect(&(m->frame));
	putchar('\n');

	_iprintf("Frame rate: %f / sec.\n", m->rate);
	_iprintf("Total frames: %i\n", m->nFrames);
}

void
outputTrailer (struct Movie *m)
{
}

void
outputBlock (int type, SWF_Parserstruct * blockp, FILE* stream)
{
  int i;

  if(blockp == NULL)
	return;

  int offset = blockp->offset;
  int length = blockp->length;

  if (type < 0)
    return;

#if defined(ACTIONONLY)
  if( type != SWF_DOACTION &&
      type != SWF_INITACTION &&
      type != SWF_DEFINEBUTTON2 &&
      type != SWF_PLACEOBJECT2 ) return;
#endif

  putchar('\n');
  _iprintf( "Offset: %d (0x%4.4x)\n", offset, offset );
  _iprintf( "Block type: %d (%s)\n", type, blockName(type) );
  _iprintf( "Block length: %d\n", length );
  putchar('\n');

  for (i = 0; i < numOutputs; i++)
    {
      if (outputs[i].type == type)
	{
	  outputs[i].output (blockp);
	  return;
	}
    }
  outputSWF_UNKNOWNBLOCK(blockp);
  return;
}
