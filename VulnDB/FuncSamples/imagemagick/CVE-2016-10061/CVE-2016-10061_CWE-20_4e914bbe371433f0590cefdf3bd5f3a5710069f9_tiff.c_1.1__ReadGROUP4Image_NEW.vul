static Image *ReadGROUP4Image(const ImageInfo *image_info,
  ExceptionInfo *exception)
{
  char
    filename[MagickPathExtent];

  FILE
    *file;

  Image
    *image;

  ImageInfo
    *read_info;

  int
    c,
    unique_file;

  MagickBooleanType
    status;

  size_t
    length;

  ssize_t
    offset,
    strip_offset;

  /*
    Open image file.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickCoreSignature);
  if (image_info->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
      image_info->filename);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickCoreSignature);
  image=AcquireImage(image_info,exception);
  status=OpenBlob(image_info,image,ReadBinaryBlobMode,exception);
  if (status == MagickFalse)
    {
      image=DestroyImageList(image);
      return((Image *) NULL);
    }
  /*
    Write raw CCITT Group 4 wrapped as a TIFF image file.
  */
  file=(FILE *) NULL;
  unique_file=AcquireUniqueFileResource(filename);
  if (unique_file != -1)
    file=fdopen(unique_file,"wb");
  if ((unique_file == -1) || (file == (FILE *) NULL))
    ThrowImageException(FileOpenError,"UnableToCreateTemporaryFile");
  length=fwrite("\111\111\052\000\010\000\000\000\016\000",1,10,file);
  length=fwrite("\376\000\003\000\001\000\000\000\000\000\000\000",1,12,file);
  length=fwrite("\000\001\004\000\001\000\000\000",1,8,file);
  length=WriteLSBLong(file,image->columns);
  length=fwrite("\001\001\004\000\001\000\000\000",1,8,file);
  length=WriteLSBLong(file,image->rows);
  length=fwrite("\002\001\003\000\001\000\000\000\001\000\000\000",1,12,file);
  length=fwrite("\003\001\003\000\001\000\000\000\004\000\000\000",1,12,file);
  length=fwrite("\006\001\003\000\001\000\000\000\000\000\000\000",1,12,file);
  length=fwrite("\021\001\003\000\001\000\000\000",1,8,file);
  strip_offset=10+(12*14)+4+8;
  length=WriteLSBLong(file,(size_t) strip_offset);
  length=fwrite("\022\001\003\000\001\000\000\000",1,8,file);
  length=WriteLSBLong(file,(size_t) image_info->orientation);
  length=fwrite("\025\001\003\000\001\000\000\000\001\000\000\000",1,12,file);
  length=fwrite("\026\001\004\000\001\000\000\000",1,8,file);
  length=WriteLSBLong(file,image->rows);
  length=fwrite("\027\001\004\000\001\000\000\000\000\000\000\000",1,12,file);
  offset=(ssize_t) ftell(file)-4;
  length=fwrite("\032\001\005\000\001\000\000\000",1,8,file);
  length=WriteLSBLong(file,(size_t) (strip_offset-8));
  length=fwrite("\033\001\005\000\001\000\000\000",1,8,file);
  length=WriteLSBLong(file,(size_t) (strip_offset-8));
  length=fwrite("\050\001\003\000\001\000\000\000\002\000\000\000",1,12,file);
  length=fwrite("\000\000\000\000",1,4,file);
  length=WriteLSBLong(file,(long) image->resolution.x);
  length=WriteLSBLong(file,1);
  status=MagickTrue;
  for (length=0; (c=ReadBlobByte(image)) != EOF; length++)
    if (fputc(c,file) != c)
      status=MagickFalse;
  offset=(ssize_t) fseek(file,(ssize_t) offset,SEEK_SET);
  length=WriteLSBLong(file,(unsigned int) length);
  (void) fclose(file);
  (void) CloseBlob(image);
  image=DestroyImage(image);
  /*
    Read TIFF image.
  */
  read_info=CloneImageInfo((ImageInfo *) NULL);
  (void) FormatLocaleString(read_info->filename,MagickPathExtent,"%s",filename);
  image=ReadTIFFImage(read_info,exception);
  read_info=DestroyImageInfo(read_info);
  if (image != (Image *) NULL)
    {
      (void) CopyMagickString(image->filename,image_info->filename,
        MagickPathExtent);
      (void) CopyMagickString(image->magick_filename,image_info->filename,
        MagickPathExtent);
      (void) CopyMagickString(image->magick,"GROUP4",MagickPathExtent);
    }
  (void) RelinquishUniqueFileResource(filename);
  if (status == MagickFalse)
    image=DestroyImage(image);
  return(image);
}
