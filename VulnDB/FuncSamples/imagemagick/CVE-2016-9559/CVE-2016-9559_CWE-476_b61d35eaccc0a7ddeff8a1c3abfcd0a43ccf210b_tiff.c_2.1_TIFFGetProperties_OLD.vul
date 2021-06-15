static void TIFFGetProperties(TIFF *tiff,Image *image,ExceptionInfo *exception)
{
  char
    message[MagickPathExtent],
    *text;

  uint32
    count,
    length,
    type;

  unsigned long
    *tietz;


  if (TIFFGetField(tiff,TIFFTAG_ARTIST,&text) == 1)
    (void) SetImageProperty(image,"tiff:artist",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_COPYRIGHT,&text) == 1)
    (void) SetImageProperty(image,"tiff:copyright",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_DATETIME,&text) == 1)
    (void) SetImageProperty(image,"tiff:timestamp",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_DOCUMENTNAME,&text) == 1)
    (void) SetImageProperty(image,"tiff:document",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_HOSTCOMPUTER,&text) == 1)
    (void) SetImageProperty(image,"tiff:hostcomputer",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_IMAGEDESCRIPTION,&text) == 1)
    (void) SetImageProperty(image,"comment",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_MAKE,&text) == 1)
    (void) SetImageProperty(image,"tiff:make",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_MODEL,&text) == 1)
    (void) SetImageProperty(image,"tiff:model",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_OPIIMAGEID,&count,&text) == 1)
    {
      if (count >= MagickPathExtent)
        count=MagickPathExtent-1;
      (void) CopyMagickString(message,text,count+1);
      (void) SetImageProperty(image,"tiff:image-id",message,exception);
    }
  if (TIFFGetField(tiff,TIFFTAG_PAGENAME,&text) == 1)
    (void) SetImageProperty(image,"label",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_SOFTWARE,&text) == 1)
    (void) SetImageProperty(image,"tiff:software",text,exception);
  if (TIFFGetField(tiff,33423,&count,&text) == 1)
    {
      if (count >= MagickPathExtent)
        count=MagickPathExtent-1;
      (void) CopyMagickString(message,text,count+1);
      (void) SetImageProperty(image,"tiff:kodak-33423",message,exception);
    }
  if (TIFFGetField(tiff,36867,&count,&text) == 1)
    {
      if (count >= MagickPathExtent)
        count=MagickPathExtent-1;
      (void) CopyMagickString(message,text,count+1);
      (void) SetImageProperty(image,"tiff:kodak-36867",message,exception);
    }
  if (TIFFGetField(tiff,TIFFTAG_SUBFILETYPE,&type) == 1)
    switch (type)
    {
      case 0x01:
      {
        (void) SetImageProperty(image,"tiff:subfiletype","REDUCEDIMAGE",
          exception);
        break;
      }
      case 0x02:
      {
        (void) SetImageProperty(image,"tiff:subfiletype","PAGE",exception);
        break;
      }
      case 0x04:
      {
        (void) SetImageProperty(image,"tiff:subfiletype","MASK",exception);
        break;
      }
      default:
        break;
    }
  if (TIFFGetField(tiff,37706,&length,&tietz) == 1)
    {
      (void) FormatLocaleString(message,MagickPathExtent,"%lu",tietz[0]);
      (void) SetImageProperty(image,"tiff:tietz_offset",message,exception);
    }
}
