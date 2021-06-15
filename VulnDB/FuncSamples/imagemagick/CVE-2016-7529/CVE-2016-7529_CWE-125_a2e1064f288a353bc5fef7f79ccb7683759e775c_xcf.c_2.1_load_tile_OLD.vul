static MagickBooleanType load_tile(Image *image,Image *tile_image,
  XCFDocInfo *inDocInfo,XCFLayerInfo *inLayerInfo,size_t data_length,
  ExceptionInfo *exception)
{
  ssize_t
    y;

  register ssize_t
    x;

  register Quantum
    *q;

  ssize_t
    count;

  unsigned char
    *graydata;

  XCFPixelInfo
    *xcfdata,
    *xcfodata;

  xcfdata=(XCFPixelInfo *) AcquireQuantumMemory(data_length,sizeof(*xcfdata));
  if (xcfdata == (XCFPixelInfo *) NULL)
    ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
      image->filename);
  xcfodata=xcfdata;
  graydata=(unsigned char *) xcfdata;  /* used by gray and indexed */
  count=ReadBlob(image,data_length,(unsigned char *) xcfdata);
  if (count != (ssize_t) data_length)
    ThrowBinaryException(CorruptImageError,"NotEnoughPixelData",
      image->filename);
  for (y=0; y < (ssize_t) tile_image->rows; y++)
  {
    q=GetAuthenticPixels(tile_image,0,y,tile_image->columns,1,exception);
    if (q == (Quantum *) NULL)
      break;
    if (inDocInfo->image_type == GIMP_GRAY)
      {
        for (x=0; x < (ssize_t) tile_image->columns; x++)
        {
          SetPixelGray(tile_image,ScaleCharToQuantum(*graydata),q);
          SetPixelAlpha(tile_image,ScaleCharToQuantum((unsigned char)
            inLayerInfo->alpha),q);
          graydata++;
          q+=GetPixelChannels(tile_image);
        }
      }
    else
      if (inDocInfo->image_type == GIMP_RGB)
        {
          for (x=0; x < (ssize_t) tile_image->columns; x++)
          {
            SetPixelRed(tile_image,ScaleCharToQuantum(xcfdata->red),q);
            SetPixelGreen(tile_image,ScaleCharToQuantum(xcfdata->green),q);
            SetPixelBlue(tile_image,ScaleCharToQuantum(xcfdata->blue),q);
            SetPixelAlpha(tile_image,xcfdata->alpha == 255U ? TransparentAlpha :
              ScaleCharToQuantum((unsigned char) inLayerInfo->alpha),q);
            xcfdata++;
            q+=GetPixelChannels(tile_image);
          }
        }
     if (SyncAuthenticPixels(tile_image,exception) == MagickFalse)
       break;
  }
  xcfodata=(XCFPixelInfo *) RelinquishMagickMemory(xcfodata);
  return MagickTrue;
}
