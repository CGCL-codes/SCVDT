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

#include <math.h>
#include <stdarg.h>
#include <string.h>

#include "blocks/blocktypes.h"
#include "decompile.h"
#include "parser.h"
#include "swfoutput.h"

extern char *swftargetfile;

/*
 * This file contains output functions that can convert the different SWF block
 * types into libming API calls that can recreate the block. Because the Ming
 * API usage is the same independent of the language being used, this file
 * can be used for multiple language bindings (OK, maybe not LISP). The
 * difference in syntax can be paramterized so the code in #ifdefs is not
 * a lot of duplicated code.
 */
#if !defined(SWFPHP) && !defined(SWFPERL) && !defined(SWFPYTHON) && !defined(SWFPLUSPLUS) && !defined(SWFTCL)
#error "You must define SWFPHP or SWFPERL or SWFPYTHON or SWFPLUSPLUS or SWFTCL when building this file"
#endif

#ifdef SWFPERL
#define COMMSTART "#"
#define COMMEND   ""
#define VAR       "$"
#define DECLOBJ(x) "$" 
#define MEMBER    "->"
#define OBJPREF   "SWF::"
#define NEWOP     "new"
#define SQ	"'"
#define ARGSEP	","
#define ARGSTART "("
#define ARGEND	")"
#define STMNTEND ";"
#endif
#ifdef SWFPHP
#define COMMSTART "/*"
#define COMMEND   "*/"
#define VAR       "$"
#define DECLOBJ(x) "$" 
#define MEMBER    "->"
#define OBJPREF   "SWF"
#define NEWOP     "new"
#define SQ	"'"
#define ARGSEP	","
#define ARGSTART "("
#define ARGEND	")"
#define STMNTEND ";"
#endif
#ifdef SWFPYTHON
#define COMMSTART "#"
#define COMMEND   ""
#define VAR       ""
#define DECLOBJ(x) ""
#define MEMBER    "."
#define OBJPREF   "SWF"
#define NEWOP     ""
#define SQ	"'"
#define ARGSEP	","
#define ARGSTART "("
#define ARGEND	")"
#define STMNTEND ";"
#endif
#ifdef SWFPLUSPLUS
#define COMMSTART "//"
#define COMMEND   ""
#define VAR       ""
#define DECLOBJ(x) "SWF" #x "* " 
#define MEMBER    "->"
#define OBJPREF   "SWF"
#define NEWOP     "new"
#define SQ	"\""
#define ARGSEP	","
#define ARGSTART "("
#define ARGEND	")"
#define STMNTEND ";"
#endif
#ifdef SWFTCL
#define COMMSTART "#"
#define COMMEND   ""
#define VAR       "$"
#define DECLOBJ(x) "SWF" #x "* " 
#define MEMBER    " "
#define OBJPREF   "SWF"
#define NEWOP     "new"
#define SQ	""
#define ARGSEP	" "
#define ARGSTART ""
#define ARGEND	""
#define STMNTEND ""
#endif

static int framenum = 1;
static int spframenum = 1;
static int spritenum = 0;
static char spritename[64];
static int offsetX=0;
static int offsetY=0;

struct FONTINFO {		/* a linked list for all our font code info: */
 int *fontcodeptr;		/* built in several outputSWF_DEFINEFONTxxxx(), used in outputSWF_TEXT_RECORD() */
 int fontcodearrsize;
 int fontcodeID;
 struct FONTINFO *next;
};
static struct FONTINFO *fip; 	/* start point of list */
static struct FONTINFO *fip_current; 
#define OUT_BEGIN(block) \
	struct block *sblock = (struct block *)pblock; \
	printf( "\n" COMMSTART " " #block " " COMMEND "\n");

#define OUT_BEGIN_EMPTY(block) \
	printf( "\n" COMMSTART " " #block " " COMMEND "\n");

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
  {SWF_DEFINELOSSLESS, outputSWF_DEFINELOSSLESS},
  {SWF_DEFINELOSSLESS2, outputSWF_DEFINELOSSLESS2},
  {SWF_DEFINEMORPHSHAPE, outputSWF_DEFINEMORPHSHAPE},
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
  {SWF_END, outputSWF_END},
  {SWF_EXPORTASSETS, outputSWF_EXPORTASSETS},
  {SWF_FONTREF, outputSWF_FONTREF},
  {SWF_FRAMELABEL, outputSWF_FRAMELABEL},
  {SWF_FRAMETAG, outputSWF_FRAMETAG},
  {SWF_FREEALL, outputSWF_FREEALL},
  {SWF_FREECHARACTER, outputSWF_FREECHARACTER},
  {SWF_GENCOMMAND, outputSWF_GENCOMMAND},
  {SWF_IMPORTASSETS, outputSWF_IMPORTASSETS},
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
  {SWF_SYNCFRAME, outputSWF_SYNCFRAME},
  {SWF_INITACTION, outputSWF_INITACTION},
  {SWF_VIDEOFRAME, outputSWF_VIDEOFRAME},
  {SWF_METADATA, outputSWF_METADATA},
  {SWF_SETTABINDEX, outputSWF_SETTABINDEX},
  {SWF_SCRIPTLIMITS, outputSWF_SCRIPTLIMITS},
  {SWF_SYMBOLCLASS, outputSWF_SYMBOLCLASS},
  {SWF_DEFINESCENEANDFRAMEDATA, outputSWF_DEFINESCENEANDFRAMEDATA},
};

static int numOutputs = sizeof (outputs) / sizeof (struct SWFBlockOutput);

#if defined(SWFPLUSPLUS)
static char **g_varlist;
static int g_nvars;

static void add_var(const char *var)
{
    g_nvars++;
    g_varlist = (char **)realloc(g_varlist, g_nvars*sizeof(void*));
    g_varlist[g_nvars - 1] = strdup(var);
}

static int search_var(const char *var)
{
    int i;
    for (i = 0; i < g_nvars; i++)
        if (0 == strcmp(g_varlist[i], var))
            return 1;
    add_var(var);
    return 0;
}
#else
#define search_var(n) 0
#endif

/* Handle language syntax differnces with these function */

static void
init_script()
{
	static int initialized = 0;
	if ( initialized ) return;
#ifdef SWFPHP
	setNewLineString("\n");
#endif
#ifdef SWFPERL
	setNewLineString("\n");
#endif
	initialized = 1;

}


char *
methodcall (char *varname, char *method)
{
  static char buf[256];

#if defined(SWFTCL)
  sprintf (buf, "%s " VAR "%s ", method, varname);
#else
  sprintf (buf, VAR "%s" MEMBER "%s", varname, method);
#endif

  return buf;
}

void
params(int nparam, ...)
{
va_list ap;
char *fmt;
unsigned long p;
int i;

va_start(ap,nparam);
printf("%s", ARGSTART);
for(i=0;i<nparam;i++) {
	fmt = va_arg(ap,char *);
	p = va_arg(ap,unsigned long);
	printf(fmt,p);
	if( i<nparam-1 )
		printf(ARGSEP " ");
}
printf("%s", ARGEND);
va_end(ap);
}

char *
newobj (char *varname, char *obj)
{
  static char buf[256];

  if (varname)
  {
#if defined(SWFPLUSPLUS)
    // might be worth storing the newly created object in a std::auto_ptr here
    // as I dubt we're outputting nested scopes anyway..
    if (!search_var(varname))
        sprintf (buf, OBJPREF "%s* %s = " NEWOP " " OBJPREF "%s", obj, varname, obj);
    else
        sprintf (buf, "%s = " NEWOP " " OBJPREF "%s", varname, obj);
#elif defined(SWFTCL)
    sprintf (buf, "set %s [" NEWOP OBJPREF "%s]", varname, obj);
#else
    sprintf (buf, VAR "%s = " NEWOP " " OBJPREF "%s", varname, obj);
#endif
  }
  else
    sprintf (buf, NEWOP " " OBJPREF "%s", obj);

  return buf;
}

/* Output basic Flash Types */

void
outputSWF_RGBA (SWF_RGBA * color, char *pname)
{
#ifdef SWFPLUSPLUS
  char varname[256];
  sprintf(varname, "%s_red", pname);
  if (!search_var(varname))
  {
    printf ("int %s_red   = 0x%2.2x;\n", pname, color->red);
    printf ("int %s_green = 0x%2.2x;\n", pname, color->green);
    printf ("int %s_blue  = 0x%2.2x;\n", pname, color->blue);
    printf ("int %s_alpha = 0x%2.2x;\n", pname, color->alpha);
  } else
  {
    printf ("%s_red   = 0x%2.2x;\n", pname, color->red);
    printf ("%s_green = 0x%2.2x;\n", pname, color->green);
    printf ("%s_blue  = 0x%2.2x;\n", pname, color->blue);
    printf ("%s_alpha = 0x%2.2x;\n", pname, color->alpha);
  }
#else
  printf ("" VAR "%s_red   = 0x%2.2x;\n", pname, color->red);
  printf ("" VAR "%s_green = 0x%2.2x;\n", pname, color->green);
  printf ("" VAR "%s_blue  = 0x%2.2x;\n", pname, color->blue);
  printf ("" VAR "%s_alpha = 0x%2.2x;\n", pname, color->alpha);
#endif
}

void
outputSWF_MATRIX (SWF_MATRIX * matrix, char *fname)
{
  float a, b, c, d;
  float angle, xScale, yScale, skew;

  a = matrix->ScaleX;
  b = matrix->RotateSkew0;
  c = matrix->RotateSkew1;
  d = matrix->ScaleY;

  xScale = sqrt (a * a + c * c);	/* always >= 0 */
  if (a<0)
   xScale *= -1;			/* preserve sign if needed */
  yScale = (a * d - b * c) / xScale;
  skew = (a * b + c * d) / (a * a + c * c);

  if (a == 0)
    {
      if (c < 0)
	angle = -90;
      else
	angle = 90;
    }
  else
    {
      angle = atan (c / a) * 180 / M_PI;

      if (a < 0)
	{
	  if (angle < 0)
	    angle += 180;
	  else
	    angle -= 180;
	}
    }

#define TOLERANCE 0.02

  if (skew < -TOLERANCE || skew > TOLERANCE)
    printf ("%s(%f);\n", methodcall (fname, "skewXTo"), skew);

  if (matrix->HasScale)
  {
  if (xScale > 1.0 - TOLERANCE && xScale < 1.0 + TOLERANCE)
    xScale = 1.0;

  if (yScale > 1.0 - TOLERANCE && yScale < 1.0 + TOLERANCE)
    yScale = 1.0;

  if (xScale != 1.0 || yScale != 1.0)
    {
      if (xScale == yScale)
	printf ("%s(%f);\n", methodcall (fname, "scaleTo"), xScale);
      else
	printf ("%s(%f, %f);\n", methodcall (fname, "scaleTo"), xScale,
		yScale);
    }
  }

  if (matrix->HasRotate)
   if (angle < -TOLERANCE || angle > TOLERANCE)
    printf ("%s(%f);\n", methodcall (fname, "rotateTo"), angle);

  if (matrix->TranslateX != 0 || matrix->TranslateY != 0)
    printf ("%s(%ld, %ld);\n", methodcall (fname, "moveTo"),
	    matrix->TranslateX, matrix->TranslateY);
}

static void
prepareSWF_MATRIX (SWF_MATRIX * matrix, SWF_RECT *shapeBounds)
{
 if (shapeBounds)
  if (shapeBounds->Xmax-shapeBounds->Xmin && shapeBounds->Ymax-shapeBounds->Ymin) 
  {
   matrix->ScaleX*=(32768.0/(shapeBounds->Xmax-shapeBounds->Xmin));
   matrix->ScaleY*=(32768.0/(shapeBounds->Ymax-shapeBounds->Ymin));
   matrix->RotateSkew1*=(32768.0/(shapeBounds->Xmax-shapeBounds->Xmin));
   matrix->RotateSkew0*=(32768.0/(shapeBounds->Ymax-shapeBounds->Ymin));
   matrix->TranslateX = (long)(matrix->TranslateX*32768) / (long)(shapeBounds->Xmax-shapeBounds->Xmin) - 16384;
   matrix->TranslateY = (long)(matrix->TranslateY*32768) / (long)(shapeBounds->Ymax-shapeBounds->Ymin) - 16384;
  }
}

static void
outputSWF_CXFORMWITHALPHA(SWF_CXFORMWITHALPHA * cxform, char *name)
{
 if (cxform->HasMultTerms)
 {
  printf("%s" ARGSTART "%0.2f" ARGSEP "%0.2f" ARGSEP "%0.2f" ARGSEP "%0.2f" ARGEND STMNTEND "\n",
    methodcall (name, "multColor"), cxform->RedMultTerm/256.0,
    cxform->GreenMultTerm/256.0, cxform->BlueMultTerm/256.0, cxform->AlphaMultTerm/256.0);
 }
 if (cxform->HasAddTerms)
 {
  printf("%s" ARGSTART "%ld" ARGSEP "%ld" ARGSEP "%ld" ARGSEP "%ld" ARGEND STMNTEND "\n",
    methodcall (name, "addColor"),  cxform->RedAddTerm,
    cxform->GreenAddTerm, cxform->BlueAddTerm, cxform->AlphaAddTerm);
 }	
}

static char*
getButtonCondString(SWF_BUTTONCONDACTION *flags)
{
  if ( flags->CondOverUpToOverDown ) return ("SWFBUTTON_MOUSEDOWN");
  if ( flags->CondOverDownToOverUp ) return ("SWFBUTTON_MOUSEUP");
  if ( flags->CondIdleToOverUp )     return ("SWFBUTTON_MOUSEOVER");
  if ( flags->CondOverUpToIdle )     return ("SWFBUTTON_MOUSEOUT");
  if ( flags->CondIdleToOverDown )   return ("SWFBUTTON_DRAGOVER");
  if ( flags->CondOutDownToOverDown) return ("SWFBUTTON_DRAGOVER");
  if ( flags->CondOutDownToIdle )    return ("SWFBUTTON_MOUSEUPOUTSIDE");
  if ( flags->CondOverDownToIdle )   return ("SWFBUTTON_DRAGOUT");
  return "unknown_flag";
}

static char*
getEventString(SWF_CLIPEVENTFLAGS *clipevflags)
{
  if ( clipevflags->ClipEventKeyUp ) return ("SWFACTION_KEYUP");
  if ( clipevflags->ClipEventKeyDown ) return ("SWFACTION_KEYDOWN");
  if ( clipevflags->ClipEventMouseUp ) return ("SWFACTION_MOUSEUP");
  if ( clipevflags->ClipEventMouseDown ) return ("SWFACTION_MOUSEDOWN");
  if ( clipevflags->ClipEventMouseMove ) return ("SWFACTION_MOUSEMOVE");
  if ( clipevflags->ClipEventUnload ) return ("SWFACTION_UNLOAD");
  if ( clipevflags->ClipEventEnterFrame ) return ("SWFACTION_ENTERFRAME");
  if ( clipevflags->ClipEventLoad ) return ("SWFACTION_ONLOAD");
  if ( clipevflags->ClipEventDragOver ) return ("SWFACTION_DRAGOVER");
  if ( clipevflags->ClipEventRollOut ) return ("SWFACTION_ROLLOUT");
  if ( clipevflags->ClipEventRollOver ) return ("SWFACTION_ROLLOVER");
  if ( clipevflags->ClipEventReleaseOutside ) return ("SWFACTION_RELEASEOUTSIDE");
  if ( clipevflags->ClipEventRelease ) return ("SWFACTION_RELEASE");
  if ( clipevflags->ClipEventPress ) return ("SWFACTION_PRESS");
  if ( clipevflags->ClipEventInitialize ) return ("SWFACTION_INIT");
  if ( clipevflags->ClipEventData ) return ("SWFACTION_DATA");
  if ( clipevflags->ClipEventConstruct ) return ("SWFACTION_CONSTRUCT");
  if ( clipevflags->ClipEventKeyPress ) return ("SWFACTION_KEYPRESS");
  if ( clipevflags->ClipEventDragOut ) return ("SWFACTION_DRAGOUT");
  return "unknown_flag";
}

void
outputSWF_CLIPACTIONS (SWF_CLIPACTIONS * clipactions, char *sname)
{
  int i;
/*  printf( COMMSTART " %d clip actions " COMMEND "\n", clipactions->NumClipRecords );*/
  for (i = 0; i < clipactions->NumClipRecords-1 ; i++)
  {
    printf ("%s(%s(\"%s\"),%s);\n\n", methodcall (sname, "addAction"), newobj (NULL, "Action"), 
	decompile5Action(clipactions->ClipActionRecords[i].numActions,
	clipactions->ClipActionRecords[i].Actions, 0),
	getEventString( &clipactions->ClipActionRecords[i].EventFlag)
  );	
 }
}

void
outputSWF_GRADIENT (SWF_GRADIENT * gradient, char *gname)
{
  int i;
  printf ("%s();\n", newobj (gname, "Gradient"));
  for (i = 0; i < gradient->NumGradients; i++)
    printf ("%s(%f,0x%2.2x,0x%2.2x,0x%2.2x,0x%2.2x);\n",
	    methodcall (gname, "addEntry"),
	    (gradient->GradientRecords[i].Ratio / 255.0),
	    gradient->GradientRecords[i].Color.red,
	    gradient->GradientRecords[i].Color.green,
	    gradient->GradientRecords[i].Color.blue,
	    gradient->GradientRecords[i].Color.alpha);
}

void
outputSWF_FILLSTYLE_new (SWF_FILLSTYLE * fillstyle, char *parentname, int i, SWF_RECT *shapeBounds)
{
  char fname[64];
  char gname[64];
  const char* fillTypeName = NULL;
  int do_declare;

  sprintf (fname, "%s_f%d", parentname, i);
  do_declare = !search_var(fname);

  switch (fillstyle->FillStyleType)
    {
    case 0x00:			/* Solid Fill */
      outputSWF_RGBA (&fillstyle->Color, fname);
      if (do_declare)
        printf ("" DECLOBJ(Fill) " ");
      printf ("%s = %s(" VAR "%s_red, "
	      VAR "%s_green, "
	      VAR "%s_blue, "
	      VAR "%s_alpha "
	      "); " COMMSTART "SWFFILL_SOLID" COMMEND "\n",
	      fname,
	      methodcall (parentname, "addSolidFill"), fname, fname, fname, fname);
      break;
    case 0x10:			/* Linear Gradient Fill */
      sprintf (gname, "%s_g%d", parentname, i);
      outputSWF_GRADIENT (&fillstyle->Gradient, gname);
      if (do_declare)
        printf ("" DECLOBJ(Fill) " ");
      printf ("%s = %s(" VAR "%s,SWFFILL_LINEAR_GRADIENT);\n",
	      fname, methodcall (parentname, "addGradientFill"), gname);
      if (shapeBounds)
        prepareSWF_MATRIX(&fillstyle->GradientMatrix, shapeBounds);
      outputSWF_MATRIX (&fillstyle->GradientMatrix, fname);
      break;
    case 0x12:			/* Radial Gradient Fill */
      sprintf (gname, "%s_g%d", parentname, i);
      outputSWF_GRADIENT (&fillstyle->Gradient, gname);
      if (do_declare)
        printf ("" DECLOBJ(Fill) " ");
      printf ("%s = %s(" VAR "%s,SWFFILL_RADIAL_GRADIENT);\n",
	      fname, methodcall (parentname, "addGradientFill"), gname);
      if (shapeBounds)
        prepareSWF_MATRIX(&fillstyle->GradientMatrix, shapeBounds);
      outputSWF_MATRIX (&fillstyle->GradientMatrix, fname);
      break;

    case 0x40:			/* Repeating Bitmap Fill */
             fillTypeName = "SWFFILL_TILED_BITMAP";
    case 0x41:			/* Clipped Bitmap Fill */
      if ( ! fillTypeName )
             fillTypeName = "SWFFILL_CLIPPED_BITMAP";
    case 0x42:			/* Non-smoothed Repeating Bitmap Fill */
      if ( ! fillTypeName )
             fillTypeName = "SWFFILL_NONSMOOTHED_TILED_BITMAP";
    case 0x43:			/* Non-smoothed Clipped Bitmap Fill */
      if ( ! fillTypeName )
             fillTypeName = "SWFFILL_NONSMOOTHED_CLIPPED_BITMAP";
      /*
       * TODO:
       *  - specially handle a CharacterID of 65535 (it occurs!)
       */
      printf (COMMSTART " BitmapID: %d " COMMEND "\n", fillstyle->BitmapId);
      sprintf (gname, "character%d", fillstyle->BitmapId);
      if (do_declare)
        printf ("" DECLOBJ(Fill) " ");
      printf ("%s = %s(" VAR "%s,%s);\n",
	      fname, methodcall (parentname, "addBitmapFill"),
              gname, fillTypeName);
      outputSWF_MATRIX (&fillstyle->BitmapMatrix, fname);
      break;
  }
}

void
outputSWF_FILLSTYLEARRAY_new (SWF_FILLSTYLEARRAY * fillstylearray,
			  char *parentname,SWF_RECT *shapeBounds)
{
  int i, count;

  count = (fillstylearray->FillStyleCount != 0xff) ?
    fillstylearray->FillStyleCount : fillstylearray->FillStyleCountExtended;

  printf ("" COMMSTART "%d fillstyle(s)" COMMEND "\n", count);

  for (i = 0; i < count; i++)
    {
      outputSWF_FILLSTYLE_new (&(fillstylearray->FillStyles[i]), parentname, i,shapeBounds);
    }
}

void
outputSWF_LINESTYLE (SWF_LINESTYLE * linestyle, char *parentname, int i)
{
  char lname[64], varname[256];
  sprintf (lname, "%s_l%d", parentname, i);
  sprintf (varname, "%s_l%d_width", parentname, i);
#ifdef SWFPLUSPLUS
  if (!search_var(varname))
    printf ("int %s = %d;\n", varname, linestyle->Width);
  else
    printf ("%s = %d;\n", varname, linestyle->Width);
#else
  printf ("" VAR "%s = %d;\n", varname, linestyle->Width);
#endif

  outputSWF_RGBA (&linestyle->Color, lname);

}

void
outputSWF_LINESTYLE2 (SWF_LINESTYLE2 * linestyle, char *parentname, int i)
{
  char lname[64], varname[256];
  sprintf (lname, "%s_l%d", parentname, i);
  sprintf (varname, "%s_l%d_width", parentname, i);
#ifdef SWFPLUSPLUS
  if (!search_var(varname))
    printf ("int %s = %d;\n", varname, linestyle->Width);
  else
    printf ("%s = %d;\n", varname, linestyle->Width);
#else
  printf ("" VAR "%s = %d;\n", varname, linestyle->Width);
#endif

  /* TODO: use also all the other fields (styles) */
  printf (COMMSTART "Style information not output" COMMEND "\n");

  outputSWF_RGBA (&linestyle->Color, lname);

}

void
outputSWF_LINESTYLEARRAY (SWF_LINESTYLEARRAY * linestylearray,
			  char *parentname)
{
  int i, count;

  count = linestylearray->LineStyleCount;

  printf ("" COMMSTART "%d linestyles(s)" COMMEND "\n", count);
  for (i = 0; i < count; i++)
  {
    if(linestylearray->LineStyles != NULL)   
      outputSWF_LINESTYLE (&(linestylearray->LineStyles[i]), parentname, i);
    else if(linestylearray->LineStyles2 != NULL)
      outputSWF_LINESTYLE2 (&(linestylearray->LineStyles2[i]), parentname, i);
    else
      printf ("" COMMSTART "Unknown linestyle %d (parser error?)" COMMEND "\n", i);
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
	  if (shaperec->StraightEdge.GeneralLineFlag)
	    {
	      /* The general case */
	      printf ("%s(%ld, %ld);\n", methodcall (parentname, "drawLine"),
		      shaperec->StraightEdge.DeltaX,
		      shaperec->StraightEdge.DeltaY);
	    }
	  else
	    {
	      /* The Horizontal or Verticle case */
	      printf ("%s(%ld, %ld);\n", methodcall (parentname, "drawLine"),
		      shaperec->StraightEdge.VLDeltaX,
		      shaperec->StraightEdge.VLDeltaY);
	    }
	}
      else
	{
	  /* A Curved Edge Record */
	  printf ("%s(%ld, %ld, %ld, %ld);\n",
		  methodcall (parentname, "drawCurve"),
		  shaperec->CurvedEdge.ControlDeltaX,
		  shaperec->CurvedEdge.ControlDeltaY,
		  shaperec->CurvedEdge.AnchorDeltaX,
		  shaperec->CurvedEdge.AnchorDeltaY);
	}
    }
  else
    {
      /* A Non-Edge Record */
      if (shaperec->EndShape.EndOfShape == 0)
	{
	  return;
	}
      if (shaperec->StyleChange.StateNewStyles)
      {
	 /* output new style changes before using */
	 printf (COMMSTART "Some styles are CHANGED now:" COMMEND "\n");
	 outputSWF_LINESTYLEARRAY (&(shaperec->StyleChange.LineStyles), parentname);
	 outputSWF_FILLSTYLEARRAY_new (&(shaperec->StyleChange.FillStyles), parentname,NULL);
      }
      if (shaperec->StyleChange.StateLineStyle)
	{
	  printf (COMMSTART " StateLineStyle: %ld " COMMEND "\n", shaperec->StyleChange.LineStyle);
	  if (shaperec->StyleChange.LineStyle == 0)
	    {
	      printf ("%s(0,0,0,0,0);\n", methodcall (parentname, "setLine"));
	    }
	  else
	    {
	      /*
	       * We use the variable names that were output by
	       * outputSWF_LINESTYLE()
	       */
	      printf ("%s(" VAR "%s_l%ld_width, " VAR "%s_l%ld_red, "
		      VAR "%s_l%ld_green, " VAR "%s_l%ld_blue, "
		      VAR "%s_l%ld_alpha);\n",
		      methodcall (parentname, "setLine"),
		      parentname, shaperec->StyleChange.LineStyle - 1,
		      parentname, shaperec->StyleChange.LineStyle - 1,
		      parentname, shaperec->StyleChange.LineStyle - 1,
		      parentname, shaperec->StyleChange.LineStyle - 1,
		      parentname, shaperec->StyleChange.LineStyle - 1);
	    }
	}
      if (shaperec->StyleChange.StateFillStyle1 && shaperec->StyleChange.FillStyle1)
	{
	  printf ("%s(", methodcall (parentname, "setRightFill"));
	  if (shaperec->StyleChange.FillStyle1)
	    {
	      printf (VAR "%s_f%ld", parentname,shaperec->StyleChange.FillStyle1 - 1);
	    }
	  printf (");\n");
	}
      if (shaperec->StyleChange.StateFillStyle0 && shaperec->StyleChange.FillStyle0)
	{
	  printf ("%s(", methodcall (parentname, "setLeftFill"));
	  if (shaperec->StyleChange.FillStyle0)
	    {
	      printf (VAR "%s_f%ld", parentname,shaperec->StyleChange.FillStyle0 - 1);
	    }
	  printf (");\n");
	}
      if (shaperec->StyleChange.StateMoveTo)
	{
	  printf ("%s(%ld, %ld);\n", methodcall (parentname, "movePenTo"),
		  shaperec->StyleChange.MoveDeltaX,
		  shaperec->StyleChange.MoveDeltaY);
	}
    }

}

void
outputSWF_SHAPE (SWF_SHAPE * shape, char *name)
{
  int i;
  for (i = 0; i < shape->NumShapeRecords; i++)
    {
      outputSWF_SHAPERECORD (&(shape->ShapeRecords[i]), name);
    }
}

void
outputSWF_SHAPEWITHSTYLE_new (SWF_SHAPEWITHSTYLE * shape, int level, char *name, SWF_RECT *shapeBounds )
{
  int i;
  outputSWF_FILLSTYLEARRAY_new (&(shape->FillStyles), name, shapeBounds);
  outputSWF_LINESTYLEARRAY (&(shape->LineStyles), name);
  for (i = 0; i < shape->NumShapeRecords; i++)
    {
      outputSWF_SHAPERECORD (&(shape->ShapeRecords[i]), name);
    }
}

/* Output Flash Blocks */
void
outputSWF_CHARACTERSET (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_CHARACTERSET);

}

void
outputSWF_DEFINEBITS (SWF_Parserstruct * pblock)
{
  char name[32];

  /* TODO: use JPEGData and JPEGDataSize to actually include content. dump to a file maybe */

  OUT_BEGIN (SWF_DEFINEBITS);

  sprintf (name, "character%d", sblock->CharacterID);
  printf ("\n" COMMSTART " Bitmap %d (bits). To extract: " COMMEND "\n",
    sblock->CharacterID);
  printf (COMMSTART " swfextract -j %d -o %s.jpg $swf " COMMEND "\n",
    sblock->CharacterID, name);
  printf ("%s('%s.jpg');\n", newobj (name, "Bitmap"), name);

}

void
outputSWF_DEFINEBITSJPEG2 (SWF_Parserstruct * pblock)
{
  char name[32];

  /* TODO: use JPEGData and JPEGDataSize to actually include content. dump to a file maybe */

  OUT_BEGIN (SWF_DEFINEBITSJPEG2);

  sprintf (name, "character%d", sblock->CharacterID);
  printf ("\n" COMMSTART " Bitmap %d (jpeg2). To extract: " COMMEND "\n",
    sblock->CharacterID);
  printf (COMMSTART " swfextract -j %d -o %s.jpg $swf " COMMEND "\n",
    sblock->CharacterID, name);
  printf ("%s('%s.jpg');\n", newobj (name, "Bitmap"), name);

}

void
outputSWF_DEFINEBITSJPEG3 (SWF_Parserstruct * pblock)
{
  char name[32];

  /* TODO: use JPEGData and JPEGDataSize to actually include content. dump to a file maybe */

  OUT_BEGIN (SWF_DEFINEBITSJPEG3);

  sprintf (name, "character%d", sblock->CharacterID);
  printf ("\n" COMMSTART " Bitmap %d (jpeg3). To extract: " COMMEND "\n",
    sblock->CharacterID);
  printf (COMMSTART " swfextract -j %d -o %s.jpg $swf " COMMEND "\n",
    sblock->CharacterID, name);
  printf ("%s('%s.jpg');\n", newobj (name, "Bitmap"), name);
}

void
outputSWF_DEFINEBITSPTR (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_DEFINEBITSPTR);

}


void
outputSWF_BUTTONRECORD( SWF_BUTTONRECORD *brec, char *bname)
{
  int notFirst = 0;
  char cname[64];
  char brname[64];
  //char buttonstates[64];

  OUT_BEGIN_EMPTY (SWF_BUTTONRECORD);

  sprintf(cname, "character%d", brec->CharacterId);
  sprintf(brname, "%sbr%d", bname, brec->PlaceDepth);

  //printf ("%s(" VAR "%s,", methodcall(bname, "addCharacter"), cname);
  if (!search_var(brname))
    printf (DECLOBJ(ButtonRecord) " ");
  printf ("%s = %s(" VAR "%s,",
        brname, methodcall(bname, "addCharacter"), cname);

  if (brec->ButtonStateHitTest)
  {
    if (notFirst)
      printf(" | ");
    printf("SWFBUTTON_HIT");
    notFirst = 1;
  }
  if (brec->ButtonStateDown)
  {
    if (notFirst)
      printf(" | ");
    printf("SWFBUTTON_DOWN");
    notFirst = 1;
  }
  if (brec->ButtonStateOver)
  {
    if (notFirst)
      printf(" | ");
    printf("SWFBUTTON_OVER");
    notFirst = 1;
  }
  if (brec->ButtonStateUp)
  {
    if (notFirst)
      printf(" | ");
    printf("SWFBUTTON_UP");
    notFirst = 1;
  }
  printf (")"STMNTEND"\n");

  // ButtonRecord uses same transformation function names as DisplayItem, so this should work.
  outputSWF_MATRIX(&brec->PlaceMatrix, brname);
}

void
outputSWF_DEFINEBUTTON (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_DEFINEBUTTON);

}

void
outputSWF_DEFINEBUTTON2 (SWF_Parserstruct * pblock)
{
  int i;
  char bname[64];
  OUT_BEGIN (SWF_DEFINEBUTTON2);

  sprintf (bname, "character%d", sblock->Buttonid);
  printf ("%s()"STMNTEND"\n", newobj (bname, "Button"));
  for(i=0;i < sblock->numCharacters;i++) 
  {
    outputSWF_BUTTONRECORD( &(sblock->Characters[i]), bname );
  }
  for(i=0;i < sblock->numActions;i++) 
  {
    printf ("%s(%s(\"%s\"),%s);\n\n", methodcall (bname, "addAction"), newobj (NULL, "Action"), 
	decompile5Action(sblock->Actions[i].numActions, sblock->Actions[i].Actions,0),	
	getButtonCondString(&sblock->Actions[i]) );	
  }
}


void
outputSWF_DEFINEBUTTONCXFORM (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_DEFINEBUTTONCXFORM);

}

void
outputSWF_DEFINEBUTTONSOUND (SWF_Parserstruct * pblock)
{
  char bname[64];
  char sname[64];
  OUT_BEGIN (SWF_DEFINEBUTTONSOUND);
  sprintf (bname, "character%d", sblock->CharacterID);
  
  if (sblock->ButtonSoundChar0)
  {
   sprintf (sname, VAR "character%d", sblock->ButtonSoundChar0);
   printf ("%s(%s,%s);\n\n", methodcall (bname, "addSound"), sname, "SWFBUTTON_MOUSEOUT");
  }
  if (sblock->ButtonSoundChar1)
  {
   sprintf (sname, VAR "character%d", sblock->ButtonSoundChar1);
   printf ("%s(%s,%s);\n\n", methodcall (bname, "addSound"), sname, "SWFBUTTON_MOUSEOVER");
  }
  if (sblock->ButtonSoundChar2)
  {
   sprintf (sname, VAR "character%d", sblock->ButtonSoundChar2);
   printf ("%s(%s,%s);\n\n", methodcall (bname, "addSound"), sname, "SWFBUTTON_MOUSEDOWN");
  }
  if (sblock->ButtonSoundChar3)
  {
   sprintf (sname, VAR "character%d", sblock->ButtonSoundChar3);
   printf ("%s(%s,%s);\n\n", methodcall (bname, "addSound"), sname, "SWFBUTTON_MOUSEUP");
  }
  /* todo proc soundinstance */
}

void
outputSWF_DEFINECOMMANDOBJ (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_DEFINECOMMANDOBJ);

}

void
outputSWF_DEFINEEDITTEXT (SWF_Parserstruct * pblock)
{
  struct FONTINFO *fi=fip;
  int notFirst = 0;
  char tname[64];
  OUT_BEGIN (SWF_DEFINEEDITTEXT);

  sprintf (tname, "character%d", sblock->CharacterID);
  printf ("%s();\n", newobj (tname, "TextField"));

  printf ("%s(", methodcall (tname, "setFlags"));
  if (sblock->WordWrap)
    {
      printf ("SWFTEXTFIELD_WORDWRAP");
      notFirst = 1;
    }
  if (sblock->Multiline)
    {
      if (notFirst)
	printf (" | ");
      printf ("SWFTEXTFIELD_MULTILINE");
      notFirst = 1;
    }
  if (sblock->Password)
    {
      if (notFirst)
	printf (" | ");
      printf ("SWFTEXTFIELD_PASSWORD");
      notFirst = 1;
    }
  if (sblock->ReadOnly)
    {
      if (notFirst)
	printf (" | ");
      printf ("SWFTEXTFIELD_NOEDIT");
      notFirst = 1;
    }
/* handled by setLength later on
  if (sblock->HasMaxLength)
    {
      if (notFirst)
	printf (" | ");
      printf ("SWFTEXTFIELD_HASLENGTH");
      notFirst = 1;
    }
*/
  if (sblock->AutoSize)
    {
      if (notFirst)
	printf (" | ");
      printf ("SWFTEXTFIELD_AUTOSIZE");
      notFirst = 1;
    }
/*
if( sblock->HasLayout ) {
	if( notFirst ) printf("|");
	printf("SWFTEXTFIELD_HASLAYOUT");
	notFirst=1;
}
*/
  if (sblock->NoSelect)
    {
      if (notFirst)
	printf (" | ");
      printf ("SWFTEXTFIELD_NOSELECT");
      notFirst = 1;
    }
  if (sblock->Border)
    {
      if (notFirst)
	printf (" | ");
      printf ("SWFTEXTFIELD_DRAWBOX");
      notFirst = 1;
    }
  if (sblock->HTML)
    {
      if (notFirst)
	printf (" | ");
      printf ("SWFTEXTFIELD_HTML");
      notFirst = 1;
    }
  printf (");\n");

  printf ("%s(%ld, %ld);\n", methodcall (tname, "setBounds"),
	  sblock->Bounds.Xmax, sblock->Bounds.Ymax);
  if (sblock->HasFont)
    {
      printf ("%s(" VAR "f%d);\n", methodcall (tname, "setFont"),
	      sblock->FontID);
      printf ("%s(%d);\n", methodcall (tname, "setHeight"),
	      sblock->FontHeight);
      while (fi)
      {
       int i;
       if (fi->fontcodeID==sblock->FontID)
       {
        printf ("%s(" SQ , methodcall (tname, "addChars"));
        for(i=0;i<fi->fontcodearrsize;i++)
        {
#ifdef SWFPERL
         if (fi->fontcodeptr[i]=='\'' || fi->fontcodeptr[i]=='\\' || fi->fontcodeptr[i]=='@' || fi->fontcodeptr[i]=='%' )
          printf ("\\");
#endif
#if defined(SWFPHP) || defined(SWFPYTHON)
         if (fi->fontcodeptr[i]=='\'' || fi->fontcodeptr[i]=='\\')
          printf ("\\");
#endif
         if (fi->fontcodeptr[i]<256)
          printf ("%c",fi->fontcodeptr[i]);
        } 
        printf (SQ ");\n" );
        break;
       }
       else
        fi=fi->next;
      }
    }
  if (sblock->HasTextColor)
    {
      printf ("%s(0x%02x, 0x%02x, 0x%02x, 0x%02x);\n",
	      methodcall (tname, "setColor"),
	      sblock->TextColor.red,
	      sblock->TextColor.green,
	      sblock->TextColor.blue, sblock->TextColor.alpha);
    }
  if (sblock->HasMaxLength)
    {
      printf ("%s(%d);\n", methodcall (tname, "setLength"),
	      sblock->MaxLength);
    }
  if (sblock->HasLayout)
    {
      printf ("%s(", methodcall (tname, "align"));
      switch (sblock->Align)
	{
	case 0:
	  printf ("SWFTEXTFIELD_ALIGN_LEFT");
	  break;
	case 1:
	  printf ("SWFTEXTFIELD_ALIGN_RIGHT");
	  break;
	case 2:
	  printf ("SWFTEXTFIELD_ALIGN_CENTER");
	  break;
	case 3:
	  printf ("SWFTEXTFIELD_ALIGN_JUSTIFY");
	  break;
	}
      printf (");\n");
      printf ("%s(%d);\n", methodcall (tname, "setLeftMargin"),
	      sblock->LeftMargin);
      printf ("%s(%d);\n", methodcall (tname, "setRightMargin"),
	      sblock->RightMargin);
      printf ("%s(%d);\n", methodcall (tname, "setIndentation"),
	      sblock->Indent);
      printf ("%s(%d);\n", methodcall (tname, "setLineSpacing"),
	      sblock->Leading);
    }
  printf ("%s('%s');\n", methodcall (tname, "setName"),
	  sblock->VariableName);
  if (sblock->HasText)
    {
      printf ("%s('%s');\n", methodcall (tname, "addString"),
	      sblock->InitialText);
    }

}

void
outputSWF_DEFINEFONT (SWF_Parserstruct * pblock)
{
  char fname[64];
  OUT_BEGIN (SWF_DEFINEFONT);

  sprintf (fname, "f%d", sblock->FontID);

  printf ("\n" COMMSTART " Font %d (%d glyps)." COMMEND "\n",
    sblock->FontID, sblock->NumGlyphs);
  printf ("%s(\"font%d.fdb\" );\n", newobj (fname, "Font"), sblock->FontID);
}

/* save important part for later usage in outputSWF_DEFINETEXT(), outputSWF_DEFINETEXT2() */
static void saveFontInfo(int id,int numglyph,int *codetable,UI16 *ct16)
{
  struct FONTINFO *fi=fip;

  if (!fi) 
    fi=fip=fip_current=calloc(1,sizeof(struct FONTINFO));
  else
  {  
   while (fi->next)
     fi=fi->next; 
   fi->next=calloc(1,sizeof(struct FONTINFO));
   fi=fi->next;
  }
  if (fi)   
  {
   if (NULL != (fi->fontcodeptr=malloc(numglyph * sizeof(int))))
   {
    int i;
    for (i=0;i<numglyph;i++)
    {
     fi->fontcodeptr[i]=codetable ? codetable[i] : ct16[i];
    }
    fi->fontcodearrsize=numglyph;
    fi->fontcodeID=id;
    printf (COMMSTART " init font %d code table" COMMEND "\n",id);
   }
  }
}


void
outputSWF_DEFINEFONT2 (SWF_Parserstruct * pblock)
{
  char fname[64];
  OUT_BEGIN (SWF_DEFINEFONT2);

  sprintf (fname, "f%d", sblock->FontID);
  if (sblock->FontFlagsHasLayout || sblock->NumGlyphs)
  {
   printf (COMMSTART " font name: %s" COMMEND "\n", sblock->FontName);
   printf ("%s(\"font%d.fdb\" );\n", newobj (fname, "Font"), sblock->FontID);
   saveFontInfo(sblock->FontID,sblock->NumGlyphs,sblock->CodeTable,NULL);
  }
  else
  {
   printf ("%s(\"%s\" );\n", newobj (fname, "BrowserFont"), sblock->FontName);
  }
}

void
outputSWF_DEFINEFONT3 (SWF_Parserstruct * pblock)
{
  char fname[64];
  OUT_BEGIN (SWF_DEFINEFONT3);

  sprintf (fname, "f%d", sblock->FontID);

  if (sblock->FontFlagsHasLayout || sblock->NumGlyphs)
  {
   printf (COMMSTART " font name: %s" COMMEND "\n", sblock->FontName);
   printf ("%s(\"font%d.fdb\" );\n", newobj (fname, "Font"), sblock->FontID);
   saveFontInfo(sblock->FontID,sblock->NumGlyphs,NULL,sblock->CodeTable);
  }
  else
  {
   printf ("%s(\"%s\" );\n", newobj (fname, "BrowserFont"), sblock->FontName);
  }
}

void
outputSWF_DEFINEFONTINFO (SWF_Parserstruct * pblock)
{
  char fname[64];
  OUT_BEGIN (SWF_DEFINEFONTINFO);

  sprintf (fname, "f%d", sblock->FontID);
  printf ("%s(\"%s.fdb\" );\n", newobj (fname, "Font"), sblock->FontName);
  saveFontInfo(sblock->FontID,sblock->nGlyph,NULL,sblock->CodeTable);
}

void
outputSWF_DEFINEFONTINFO2(SWF_Parserstruct * pblock)
{
  char fname[64];
  OUT_BEGIN (SWF_DEFINEFONTINFO2);

  sprintf (fname, "f%d", sblock->FontID);
  printf ("%s(\"%s.fdb\" );\n", newobj (fname, "Font"), sblock->FontName);
  saveFontInfo(sblock->FontID,sblock->nGlyph,NULL,sblock->CodeTable);
}

void
outputSWF_DEFINELOSSLESS (SWF_Parserstruct * pblock)
{
  char name[32];

  OUT_BEGIN (SWF_DEFINELOSSLESS);

  sprintf (name, "character%d", sblock->CharacterID);
  printf ("\n" COMMSTART " Bitmap %d (lossless). To extract: " COMMEND "\n",
    sblock->CharacterID);
  printf (COMMSTART " swfextract -p %d -o %s.png $swf " COMMEND "\n",
    sblock->CharacterID, name);
  printf ("%s('%s.png');\n", newobj (name, "Bitmap"), name);

}

void
outputSWF_DEFINELOSSLESS2 (SWF_Parserstruct * pblock)
{
  char name[32];

  OUT_BEGIN (SWF_DEFINELOSSLESS2);

  sprintf (name, "character%d", sblock->CharacterID);
  printf ("\n" COMMSTART " Bitmap %d (lossless2). To extract:" COMMEND "\n",
    sblock->CharacterID);
  printf (COMMSTART " swfextract -p %d -o %s.png $swf " COMMEND "\n",
    sblock->CharacterID, name);
  printf ("%s('%s.png');\n", newobj (name, "Bitmap"), name);
}

void
outputSWF_DEFINEMORPHSHAPE (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_DEFINEMORPHSHAPE);

}

void
outputSWF_DEFINESHAPE (SWF_Parserstruct * pblock)
{
  char name[32];
  OUT_BEGIN (SWF_DEFINESHAPE);
  sprintf (name, "character%d", sblock->ShapeID);

  printf ("\n" COMMSTART " Shape %d (TYPE=1, RECT=%d,%d %d,%d)" COMMEND "\n", sblock->ShapeID,
   (int)sblock->ShapeBounds.Xmin,(int)sblock->ShapeBounds.Xmax,(int)sblock->ShapeBounds.Ymin,(int)sblock->ShapeBounds.Ymax);
  printf ("%s();\n", newobj (name, "Shape"));
  /* There doesn't seem to be a way to use this in the API 
   * it is calculated internal to teh shape object, but I'm not
   * sure it will come up with the same answer.
   outputSWF_RECT(&sblock->ShapeBounds);
   */
  outputSWF_SHAPEWITHSTYLE_new (&sblock->Shapes, 1, name, &sblock->ShapeBounds);
}

void
outputSWF_DEFINESHAPE2 (SWF_Parserstruct * pblock)
{
  char name[32];
  OUT_BEGIN (SWF_DEFINESHAPE2);
  sprintf (name, "character%d", sblock->ShapeID);

  printf ("\n" COMMSTART " Shape %d (TYPE=2, RECT=%d,%d %d,%d)" COMMEND "\n", sblock->ShapeID,
   (int)sblock->ShapeBounds.Xmin,(int)sblock->ShapeBounds.Xmax,(int)sblock->ShapeBounds.Ymin,(int)sblock->ShapeBounds.Ymax);
  printf ("%s();\n", newobj (name, "Shape"));
  /* There doesn't seem to be a way to use this in the API 
   * it is calculated internal to teh shape object, but I'm not
   * sure it will come up with the same answer.
   outputSWF_RECT(&sblock->ShapeBounds);
   */
  outputSWF_SHAPEWITHSTYLE_new (&sblock->Shapes, 2, name, &sblock->ShapeBounds);
}

void
outputSWF_DEFINESHAPE3 (SWF_Parserstruct * pblock)
{
  char name[32];
  OUT_BEGIN (SWF_DEFINESHAPE3);
  sprintf (name, "character%d", sblock->ShapeID);

  printf ("\n" COMMSTART " Shape %d (TYPE=3, RECT=%d,%d %d,%d)" COMMEND "\n", sblock->ShapeID,
   (int)sblock->ShapeBounds.Xmin,(int)sblock->ShapeBounds.Xmax,(int)sblock->ShapeBounds.Ymin,(int)sblock->ShapeBounds.Ymax);
  printf ("%s();\n", newobj (name, "Shape"));
  /* There doesn't seem to be a way to use this in the API 
   * it is calculated internal to teh shape object, but I'm not
   * sure it will come up with the same answer.
   outputSWF_RECT(&sblock->ShapeBounds);
   */
  outputSWF_SHAPEWITHSTYLE_new (&sblock->Shapes, 3, name, &sblock->ShapeBounds);

}

void
outputSWF_DEFINESHAPE4 (SWF_Parserstruct * pblock)
{
  char name[32];
  OUT_BEGIN (SWF_DEFINESHAPE4);
  sprintf (name, "character%d", sblock->ShapeID);

  printf ("\n" COMMSTART " Shape %d (TYPE=4, RECT=%d,%d %d,%d)" COMMEND "\n", sblock->ShapeID,
   (int)sblock->ShapeBounds.Xmin,(int)sblock->ShapeBounds.Xmax,(int)sblock->ShapeBounds.Ymin,(int)sblock->ShapeBounds.Ymax);
  printf ("%s();\n", newobj (name, "Shape"));
  /* There doesn't seem to be a way to use this in the API 
   * it is calculated internal to teh shape object, but I'm not
   * sure it will come up with the same answer.
   outputSWF_RECT(&sblock->ShapeBounds);
   */
  outputSWF_SHAPEWITHSTYLE_new (&sblock->Shapes, 4, name, &sblock->ShapeBounds);

}

void
outputSWF_DEFINESOUND (SWF_Parserstruct * pblock)
{
  char sname[64];
  OUT_BEGIN (SWF_DEFINESOUND);
  sprintf (sname, "character%d", sblock->SoundId);
  printf ("%s(\"FIX_MY_PARAMS\")"STMNTEND"\n", newobj (sname, "Sound"));
}

void
outputSWF_DEFINESPRITE (SWF_Parserstruct * pblock)
{
  int i;
  OUT_BEGIN (SWF_DEFINESPRITE);

  spritenum = sblock->SpriteId;
  spframenum = 1;
  sprintf(spritename,"character%d",sblock->SpriteId);
  printf ("\n\t" COMMSTART "  MovieClip %d " COMMEND "\n", sblock->SpriteId);
  printf ("%s(); " COMMSTART " %d frames " COMMEND "\n",
		  newobj (spritename, "MovieClip"), sblock->FrameCount);
  for(i=0;i<sblock->BlockCount;i++) {
	  outputBlock( sblock->tagTypes[i], sblock->Tags[i], NULL);
  }
  spritenum = 0;

}

static void
outputSWF_TEXT_RECORD (SWF_TEXTRECORD *trec, int level,char *tname,char *buffer,int bsize,int id)
{
  int i=0;
  struct FONTINFO *fi=fip;
  if ( trec->TextRecordType == 0 )
    return;
  if (trec->StyleFlagHasFont)
  {
   printf("%s(" VAR "f%d);\n", methodcall (tname, "setFont"), trec->FontID);
   printf("%s(%d);\n",methodcall(tname,"setHeight"),trec->TextHeight);
  }
  if( trec->StyleFlagHasColor )
  {
   if (level==2)
    printf ("%s(0x%02x, 0x%02x, 0x%02x, 0x%02x);\n",methodcall (tname, "setColor"),
      trec->TextColor.red,trec->TextColor.green,trec->TextColor.blue, trec->TextColor.alpha);
   else
    printf ("%s(0x%02x, 0x%02x, 0x%02x);\n",methodcall (tname, "setColor"),
      trec->TextColor.red,trec->TextColor.green,trec->TextColor.blue);
  }
  if( trec->StyleFlagHasYOffset || trec->StyleFlagHasXOffset ) 
  {
    printf ("%s(%d, %d);\n", methodcall (tname, "moveTo"),trec->XOffset,trec->YOffset);
  }
  if (trec->FontID) 
  {
    id=trec->FontID;
  }
  if (!trec->StyleFlagHasFont)				/* always check flag before use data */
  {
   fi = fip_current;					/* so cont w current font */
   id = fi->fontcodeID;					/* trigger next if */
  }
  while (fi)
  {
   if (fi->fontcodeID==id)
   {
    fip_current=fi;					/* set current font */
    for(i=0;i<trec->GlyphCount && i<bsize-1 ;i++)	/* byte n-1 will be terminator '\0' */
    {
     int off=(&(trec->GlyphEntries[i]))->GlyphIndex[0];
     if (off<fi->fontcodearrsize)
      buffer[i]=fi->fontcodeptr[off];
     else
      buffer[i]='?';		/* fallback to dummy A */
     /* printf ( COMMSTART "GlyphIndex[0] = %d  char = %d " COMMEND"\n",off,fi->fontcodeptr[off] ); */
    } 
    buffer[i]='\0'; 
    return;
   }
   else
    fi=fi->next;
  }
  buffer[0]='X';		/* fallback to dummy B */
  buffer[1]='\0'; 
}

void
outputSWF_DEFINETEXT (SWF_Parserstruct * pblock)
{
  int i,id=0;
  char name[32];
  char buffer[64];   
  OUT_BEGIN (SWF_DEFINETEXT);
  sprintf (name, "character%d", sblock->CharacterID);
  printf ("%s(1);\n", newobj (name, "Text"));
  for(i=0;i<sblock->numTextRecords;i++) 
  {
   if (!id && sblock->TextRecords[i].FontID)
     id=sblock->TextRecords[i].FontID;
   if ( sblock->TextRecords[i].TextRecordType  )
   {
     memset(buffer,0,64);
     outputSWF_TEXT_RECORD(&(sblock->TextRecords[i]), 1,name,buffer,64,id );
     printf ("%s(\"%s\");\n", methodcall (name, "addString"),buffer);
   }
  }
}

void
outputSWF_DEFINETEXT2 (SWF_Parserstruct * pblock)
{
  int i,id=0;
  char name[32];
  char buffer[64];
  OUT_BEGIN (SWF_DEFINETEXT2);
  sprintf (name, "character%d", sblock->CharacterID);
  printf ("%s(2);\n", newobj (name, "Text"));
  for(i=0;i<sblock->numTextRecords;i++) 
  {
   if (!id && sblock->TextRecords[i].FontID)
     id=sblock->TextRecords[i].FontID;
   if ( sblock->TextRecords[i].TextRecordType  )
   {
     memset(buffer,0,64);
     outputSWF_TEXT_RECORD(&(sblock->TextRecords[i]), 2,name,buffer,64,id );
     printf ("%s(\"%s\");\n", methodcall (name, "addString"),buffer);
   }
  }
}

void
outputSWF_DEFINETEXTFORMAT (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_DEFINETEXTFORMAT);

}

void
outputSWF_DEFINEVIDEO (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_DEFINEVIDEO);

}

void
outputSWF_DEFINEVIDEOSTREAM (SWF_Parserstruct * pblock)
{
  char name[32];

  OUT_BEGIN (SWF_DEFINEVIDEOSTREAM);

  sprintf (name, "character%d", sblock->CharacterID);

  /* NOTE: Ming sets NumFrames = 65535 for empty movies.. */
  if ( sblock->NumFrames && sblock->NumFrames != 65535 ) {
    printf (COMMSTART " You'll need to extract video%d.flv " COMMEND "\n",
            sblock->CharacterID);
    printf ("%s('video%d.flv');", newobj (name, "VideoStream"),
            sblock->CharacterID);
  } else {
    printf ("%s(); ", newobj (name, "VideoStream"));
  }
  printf (COMMSTART " %d frames advertised " COMMEND "\n", sblock->NumFrames);

  printf ("%s(%d, %d);\n", methodcall (name, "setDimension"),
    sblock->Width, sblock->Height);

  /* We go manual and have SWF_VIDEOFRAME trigger a nextFrame */
  printf ("%s(SWF_VIDEOSTREAM_MODE_MANUAL);\n",
    methodcall (name, "setFrameMode"));

}

void
outputSWF_DOACTION (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_DOACTION);

  printf ("%s(%s(\"%s\") );\n", methodcall (spritenum?spritename:"m", "add"),
	  newobj (NULL, "Action"), decompile5Action(sblock->numActions,sblock->Actions,0));
}

void
outputSWF_ENABLEDEBUGGER (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_ENABLEDEBUGGER);

}

void
outputSWF_END (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_END);

}

void
outputSWF_EXPORTASSETS (SWF_Parserstruct * pblock)
{
  int i;
  char name[32];
  OUT_BEGIN (SWF_EXPORTASSETS);

  for (i = 0; i < sblock->Count; i++)
  {
   sprintf (name, VAR "character%d", sblock->Tags[i]);
   printf ("%s" ARGSTART "%s" ARGSEP SQ "%s" SQ ARGEND STMNTEND "\n",
     methodcall ("m", "addExport"),name,sblock->Names[i]);
  }
  printf ("%s" ARGSTART ARGEND STMNTEND "\n",methodcall ("m", "writeExports"));
}

void
outputSWF_FONTREF (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_FONTREF);

}

void
outputSWF_FRAMELABEL (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_FRAMELABEL);

  printf ("%s("SQ"%s"SQ");\n",
	  methodcall (spritenum?spritename:"m", sblock->IsAnchor?"namedAnchor":"labelFrame"), sblock->Name );

}

void
outputSWF_FRAMETAG (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_FRAMETAG);

}

void
outputSWF_FREEALL (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_FREEALL);

}

void
outputSWF_FREECHARACTER (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_FREECHARACTER);

}

void
outputSWF_GENCOMMAND (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_GENCOMMAND);

}

void
outputSWF_IMPORTASSETS (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_IMPORTASSETS);

}

void
outputSWF_JPEGTABLES (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_JPEGTABLES);

}

void
outputSWF_NAMECHARACTER (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_NAMECHARACTER);

}

void
outputSWF_PATHSAREPOSTSCRIPT (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_PATHSAREPOSTSCRIPT);

}

void
outputSWF_PLACEOBJECT (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_PLACEOBJECT);

}

void
outputSWF_PLACEOBJECT2 (SWF_Parserstruct * pblock)
{
  char cname[64];
  OUT_BEGIN (SWF_PLACEOBJECT2);

  if( sblock->PlaceFlagHasCharacter ) {
    sprintf(cname, "character%d", sblock->CharacterId );
    if(sblock->Depth) 
    {
      char varname[64];
      sprintf(varname, "%s%d", "i" , sblock->Depth);
      if (!search_var(varname))
        printf ("" DECLOBJ(DisplayItem) " ");
      printf ("%s = %s(" VAR "%s)"STMNTEND"\n", varname,
        methodcall (spritenum?spritename:"m", "add"),     cname);

      sprintf(cname, "i%d", sblock->Depth );
      printf("%s(%d)"STMNTEND"\n", methodcall(cname, "setDepth"), sblock->Depth);
    }
    else
      printf(COMMSTART " PlaceFlagHasCharacter and Depth == 0! " COMMEND "\n");
  }
  if( sblock->PlaceFlagHasMatrix ) {
    printf(COMMSTART " PlaceFlagHasMatrix " COMMEND "\n");
    sprintf(cname, "i%d", sblock->Depth );
    if (!spritenum)				/* coordinate translation on main movie */
    {
      sblock->Matrix.TranslateX-=offsetX;
      sblock->Matrix.TranslateY-=offsetY;
    }
    outputSWF_MATRIX (&sblock->Matrix, cname);
  }
  if( sblock->PlaceFlagHasColorTransform ) {
    sprintf(cname, "i%d", sblock->Depth);
    outputSWF_CXFORMWITHALPHA(&sblock->ColorTransform, cname);
  }
  if( sblock->PlaceFlagHasRatio ) {
    printf(COMMSTART " PlaceFlagHasRatio " COMMEND "\n");
  }
  if( sblock->PlaceFlagHasName ) {
    sprintf(cname, "i%d", sblock->Depth );
    printf("%s("SQ"%s"SQ")"STMNTEND"\n", methodcall(cname, "setName"), sblock->Name);
  }
  if( sblock->PlaceFlagHasClipDepth ) {
    sprintf(cname, "i%d", sblock->Depth );
    printf("%s(%d)"STMNTEND"\n", methodcall(cname, "setMaskLevel"), sblock->ClipDepth);
  }
  if( sblock->PlaceFlagHasClipActions ) {
    sprintf(cname, "i%d", sblock->Depth );
    outputSWF_CLIPACTIONS (&sblock->ClipActions, cname);
  }

}

void
outputSWF_PLACEOBJECT3 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_PLACEOBJECT3);

}

void
outputSWF_PREBUILT (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_PREBUILT);

}

void
outputSWF_PREBUILTCLIP (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_PREBUILTCLIP);

}

void
outputSWF_PROTECT (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_PROTECT);

  if( sblock->Password == NULL ) {
  	printf ("%s();\n",
	  methodcall ("m", "protect"));
  } else{
  	printf ("%s(\"%s\");\n",
	  methodcall ("m", "protect"),sblock->Password);
  }

}

void
outputSWF_REMOVEOBJECT (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_REMOVEOBJECT);
  printf ("%s(" VAR "c%d);\n",
	  methodcall (spritenum?spritename:"m", "remove"), sblock->CharacterId);

}

void
outputSWF_REMOVEOBJECT2 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_REMOVEOBJECT2);
  printf ("%s(" VAR "i%d);\n",
	  methodcall (spritenum?spritename:"m", "remove"), sblock->Depth);

}

void
outputSWF_SERIALNUMBER (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_SERIALNUMBER);

}

void
outputSWF_SETBACKGROUNDCOLOR (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_SETBACKGROUNDCOLOR);

  printf ("%s", methodcall ("m", "setBackground"));
  params (3,"0x%02x", sblock->rgb.red,
	    "0x%02x", sblock->rgb.green,
	    "0x%02x", sblock->rgb.blue);
  printf (STMNTEND "\n");

}

void
outputSWF_SHOWFRAME (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_SHOWFRAME);

  printf ("%s", methodcall (spritenum?spritename:"m", "nextFrame"));
  params(0);
  printf (STMNTEND " " COMMSTART " end of %sframe %d " COMMEND "\n",
	  spritenum?"clip ":"",
	  spritenum?spframenum++:framenum++);
}

void
outputSWF_SOUNDSTREAMBLOCK (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_SOUNDSTREAMBLOCK);

}

void
outputSWF_SOUNDSTREAMHEAD (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_SOUNDSTREAMHEAD);

}

void
outputSWF_SOUNDSTREAMHEAD2 (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_SOUNDSTREAMHEAD2);

}

void
outputSWF_STARTSOUND (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_STARTSOUND);

}

void
outputSWF_SYNCFRAME (SWF_Parserstruct * pblock)
{
  OUT_BEGIN_EMPTY (SWF_SYNCFRAME);

}

void
outputSWF_INITACTION (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_INITACTION);

  printf (COMMSTART
    " Might be more appropriate to use addInitAction here" COMMEND "\n");

  /* NOTE: the printf must be split in two cause newobj uses
   *       a static buffer so can't be used twice to return
   *       different strings
   */

  printf ("%s(%s(",
          methodcall (spritenum?spritename:"m", "add"),
          newobj (NULL, "InitAction"));

  /* TODO: add SpriteID ? */

  printf ("%s(\"%s\")));\n",
          newobj (NULL, "Action"),
          decompile5Action(sblock->numActions,sblock->Actions,0));
}

void
outputSWF_VIDEOFRAME (SWF_Parserstruct * pblock)
{
  char name[32];

  OUT_BEGIN (SWF_VIDEOFRAME);

  sprintf (name, "character%d", sblock->StreamID);

  printf (COMMSTART " Frame %d of stream %d " COMMEND "\n",
    sblock->FrameNum, sblock->StreamID);
  printf ("%s();\n", methodcall (name, "nextFrame"));
}

void
outputSWF_METADATA (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_METADATA);

  /* TODO: escape Metadata string (might contain quotes!) */
  printf ("%s(\"%s\");\n",
          methodcall (spritenum?spritename:"m", "addMetadata"),
          sblock->Metadata);
}

void
outputSWF_SETTABINDEX (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_SETTABINDEX);

  printf("%s(%d, %d)"STMNTEND"\n", methodcall("m", "setTabIndex"),
    sblock->Depth, sblock->TabIndex);

}

void
outputSWF_SCRIPTLIMITS (SWF_Parserstruct * pblock)
{
  OUT_BEGIN (SWF_SCRIPTLIMITS);

  printf("%s(%d, %d)"STMNTEND"\n", methodcall("m", "setScriptLimits"),
    sblock->MaxRecursionDepth, sblock->ScriptTimeoutSeconds);

}

void
outputSWF_SYMBOLCLASS (SWF_Parserstruct * pblock)
{
  char cname[64];
  int i;

  OUT_BEGIN (SWF_SYMBOLCLASS);

  for(i = 0; i < sblock->SymbolCount; ++i)
  {
    struct AS_SYMBOL* sym = &(sblock->SymbolList[i]);
    sprintf(cname, "character%d", sym->SymbolId );

    printf("%s(" VAR "%s, \"%s\")"STMNTEND"\n", methodcall("m", "assignSymbol"),
      cname, sym->SymbolName);
  }

}


void
outputSWF_DEFINESCENEANDFRAMEDATA (SWF_Parserstruct * pblock)
{
  int i;

  OUT_BEGIN (SWF_DEFINESCENEANDFRAMEDATA);

  for(i = 0; i < sblock->SceneCount; ++i)
  {
    struct SCENE_DATA* sc = &(sblock->Scenes[i]);
	// SWFMovie_defineScene(m, 0, "test0");

    printf("%s(%lu, \"%s\")"STMNTEND"\n", methodcall("m", "defineScene"),
      sc->Offset, sc->Name);
  }

  for(i = 0; i < sblock->FrameLabelCount; ++i)
  {
    /* TODO: output a method for this! */
    struct FRAME_DATA* fd = &(sblock->Frames[i]);
    printf (COMMSTART " Label for frame %lu : %s " COMMEND "\n",
	  fd->FrameNum, fd->FrameLabel);
  }

}

void
outputHeader (struct Movie *m)
{
  int npending=0;
  if( m->version == 4 ) 
  {
    m->version=5;		/* a note for user follows after language dependent part */
    npending=1;
  }
#ifdef SWFPHP
  if( swftargetfile != NULL ) {
	printf ("#!/usr/bin/php\n");
  }
  printf ("<?php\n");
  if( m->version == 5 ) 
  	printf ("%s();\n\n", newobj ("m", "Movie"));
  else
  	printf ("%s(%d);\n\n", newobj ("m", "Movie"), m->version);
  printf ("ming_setscale(1.0);\n");
#endif
#ifdef SWFPERL
  printf ("#!/usr/bin/perl -w\n");
  printf
    ("# Generated by swftoperl converter included with ming. Have fun. \n\n");
  printf
    ("# Change this to your needs. If you installed perl-ming global you don't need this.\n");
  printf ("#use lib(\"/home/peter/mystuff/lib/site_perl\");\n\n");

  printf
    ("# We import all because our converter is not so clever to select only needed. ;-)\n");
  printf ("use SWF qw(:ALL);\n");
  printf
    ("# Just copy from a sample, needed to use Constants like SWFFILL_RADIAL_GRADIENT\n");
  printf ("use SWF::Constants qw(:Text :Button :DisplayItem :Fill);\n\n");
  if( m->version == 5 ) 
  	printf ("%s();\n\n", newobj ("m", "Movie"));
  else
  	printf ("$m = %s(%d);\n\n", "SWF::Movie::newSWFMovieWithVersion", m->version);
  printf ("SWF::setScale(1.0);\n");
#endif
#ifdef SWFPYTHON
  printf ("#!/usr/bin/python\n");
  printf ("from ming import *\n\n");
  if( m->version != 5 ) 
	printf ("Ming_useSWFVersion(%d);\n\n", m->version);
  printf ("%s();\n\n", newobj ("m", "Movie"));
  printf ("Ming_setScale(1.0);\n");
#endif
#ifdef SWFPLUSPLUS
  printf ("#include <mingpp.h>\n");
  printf ("\n\nmain(){\n");
  if( m->version == 5 ) 
  	printf ("%s();\n\n", newobj ("m", "Movie"));
  else
  	printf ("%s(%d);\n\n", newobj ("m", "Movie"), m->version);
  printf ("Ming_setScale(1.0);\n");
#endif
#ifdef SWFTCL
  printf ("load mingc.so mingc\n");
  printf ("%s\n", newobj ("m", "Movie"));
  if( m->version != 5 ) {
  	printf ("#%s(%d);\n\n", newobj ("m", "Movie"), m->version);
	// XXX:
  	// printf ("#add setversion here\n\n", "m", m->version);
	}
  printf (COMMSTART "add setscale here" COMMEND "\n");
#endif
  if( npending ) 
    printf( "\n" COMMSTART " Note: using v5+ syntax for script blocks (original SWF file version was 4)! " COMMEND "\n\n");
  if( m->rate != 12.0 ) 
  	printf ("%s(%f);\n", methodcall ("m", "setRate"), m->rate);
  if( m->frame.xMax != 6400 || m->frame.yMax != 4800 )
  	printf ("%s(%d, %d);\n", methodcall ("m", "setDimension"),
 			m->frame.xMax - m->frame.xMin, m->frame.yMax - m->frame.yMin);
  if (m->frame.xMin || m->frame.yMin)
  {
    offsetX= m->frame.xMin;
    offsetY= m->frame.yMin;
    printf( "\n" COMMSTART " Note: xMin and/or yMin are not 0! " COMMEND "\n\n");
  }
  if( m->nFrames != 1 )
  	printf ("%s(%i);\n", methodcall ("m", "setFrames"), m->nFrames);
}

void
outputTrailer (struct Movie *m)
{
	if( swftargetfile == NULL ) {
#ifdef SWFPHP
	printf ("\n\theader('Content-type: application/x-shockwave-flash');\n");
#endif
#ifdef SWFPERL
	printf ("#print('Content-type: application/x-shockwave-flash\\n\\n');\n");
#endif
#ifdef SWFPYTHON
	printf ("#print('Content-type: application/x-shockwave-flash\\n\\n');\n");
#endif
	if( m->version > 5 ) {
		printf ("%s(%i);\n", methodcall ("m", "output"), 9);
	} else {
		printf ("%s();\n", methodcall ("m", "output"));
	}
	} else {
	printf ("%s", methodcall ("m", "save"));
	params (1, "\"%s\"", swftargetfile);
	printf ( STMNTEND "\n");
	}
#ifdef SWFPHP
	printf ("?>\n");
#endif
#ifdef SWFPLUSPLUS
	printf ("}\n");
#endif
}

void
outputBlock (int type, SWF_Parserstruct * blockp, FILE* stream)
{
	int i;

	if (type < 0)
		return;

	init_script();

	for (i = 0; i < numOutputs; i++){
		if (outputs[i].type == type){
			outputs[i].output (blockp);
			return;
		}
	}
	printf( COMMSTART "Unknown block type %d" COMMEND "\n", type );
	return;
}
