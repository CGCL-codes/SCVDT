MagickExport Image *SpliceImage(const Image *image,
  const RectangleInfo *geometry,ExceptionInfo *exception)
{
#define SpliceImageTag  "Splice/Image"

  CacheView
    *image_view,
    *splice_view;

  Image
    *splice_image;

  MagickBooleanType
    status;

  MagickOffsetType
    progress;

  RectangleInfo
    splice_geometry;

  ssize_t
    y;

  /*
    Allocate splice image.
  */
  assert(image != (const Image *) NULL);
  assert(image->signature == MagickCoreSignature);
  if (image->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
  assert(geometry != (const RectangleInfo *) NULL);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickCoreSignature);
  splice_geometry=(*geometry);
  splice_image=CloneImage(image,image->columns+splice_geometry.width,
    image->rows+splice_geometry.height,MagickTrue,exception);
  if (splice_image == (Image *) NULL)
    return((Image *) NULL);
  if (SetImageStorageClass(splice_image,DirectClass,exception) == MagickFalse)
    {
      splice_image=DestroyImage(splice_image);
      return((Image *) NULL);
    }
  if ((IsPixelInfoGray(&splice_image->background_color) == MagickFalse) &&
      (IsGrayColorspace(splice_image->colorspace) != MagickFalse))
    (void) SetImageColorspace(splice_image,sRGBColorspace,exception);
  if ((splice_image->background_color.alpha_trait != UndefinedPixelTrait) &&
      (splice_image->alpha_trait == UndefinedPixelTrait))
    (void) SetImageAlpha(splice_image,OpaqueAlpha,exception);
  (void) SetImageBackgroundColor(splice_image,exception);
  /*
    Respect image geometry.
  */
  switch (image->gravity)
  {
    default:
    case UndefinedGravity:
    case NorthWestGravity:
      break;
    case NorthGravity:
    {
      splice_geometry.x+=(ssize_t) splice_geometry.width/2;
      break;
    }
    case NorthEastGravity:
    {
      splice_geometry.x+=(ssize_t) splice_geometry.width;
      break;
    }
    case WestGravity:
    {
      splice_geometry.y+=(ssize_t) splice_geometry.width/2;
      break;
    }
    case CenterGravity:
    {
      splice_geometry.x+=(ssize_t) splice_geometry.width/2;
      splice_geometry.y+=(ssize_t) splice_geometry.height/2;
      break;
    }
    case EastGravity:
    {
      splice_geometry.x+=(ssize_t) splice_geometry.width;
      splice_geometry.y+=(ssize_t) splice_geometry.height/2;
      break;
    }
    case SouthWestGravity:
    {
      splice_geometry.y+=(ssize_t) splice_geometry.height;
      break;
    }
    case SouthGravity:
    {
      splice_geometry.x+=(ssize_t) splice_geometry.width/2;
      splice_geometry.y+=(ssize_t) splice_geometry.height;
      break;
    }
    case SouthEastGravity:
    {
      splice_geometry.x+=(ssize_t) splice_geometry.width;
      splice_geometry.y+=(ssize_t) splice_geometry.height;
      break;
    }
  }
  /*
    Splice image.
  */
  status=MagickTrue;
  progress=0;
  image_view=AcquireVirtualCacheView(image,exception);
  splice_view=AcquireAuthenticCacheView(splice_image,exception);
#if defined(MAGICKCORE_OPENMP_SUPPORT)
  #pragma omp parallel for schedule(static,4) shared(progress,status) \
    magick_threads(image,splice_image,1,1)
#endif
  for (y=0; y < (ssize_t) splice_geometry.y; y++)
  {
    register const Quantum
      *restrict p;

    register ssize_t
      x;

    register Quantum
      *restrict q;

    if (status == MagickFalse)
      continue;
    p=GetCacheViewVirtualPixels(image_view,0,y,image->columns,1,exception);
    q=QueueCacheViewAuthenticPixels(splice_view,0,y,splice_image->columns,1,
      exception);
    if ((p == (const Quantum *) NULL) || (q == (Quantum *) NULL))
      {
        status=MagickFalse;
        continue;
      }
    for (x=0; x < splice_geometry.x; x++)
    {
      register ssize_t
        i;

      if (GetPixelReadMask(image,p) == 0)
        {
          SetPixelBackgoundColor(splice_image,q);
          p+=GetPixelChannels(image);
          q+=GetPixelChannels(splice_image);
          continue;
        }
      for (i=0; i < (ssize_t) GetPixelChannels(image); i++)
      {
        PixelChannel channel=GetPixelChannelChannel(image,i);
        PixelTrait traits=GetPixelChannelTraits(image,channel);
        PixelTrait splice_traits=GetPixelChannelTraits(splice_image,channel);
        if ((traits == UndefinedPixelTrait) ||
            (splice_traits == UndefinedPixelTrait))
          continue;
        SetPixelChannel(splice_image,channel,p[i],q);
      }
      SetPixelRed(splice_image,GetPixelRed(image,p),q);
      SetPixelGreen(splice_image,GetPixelGreen(image,p),q);
      SetPixelBlue(splice_image,GetPixelBlue(image,p),q);
      SetPixelAlpha(splice_image,GetPixelAlpha(image,p),q);
      p+=GetPixelChannels(image);
      q+=GetPixelChannels(splice_image);
    }
    for ( ; x < (ssize_t) (splice_geometry.x+splice_geometry.width); x++)
      q+=GetPixelChannels(splice_image);
    for ( ; x < (ssize_t) splice_image->columns; x++)
    {
      register ssize_t
        i;

      if (GetPixelReadMask(image,p) == 0)
        {
          SetPixelBackgoundColor(splice_image,q);
          p+=GetPixelChannels(image);
          q+=GetPixelChannels(splice_image);
          continue;
        }
      for (i=0; i < (ssize_t) GetPixelChannels(image); i++)
      {
        PixelChannel channel=GetPixelChannelChannel(image,i);
        PixelTrait traits=GetPixelChannelTraits(image,channel);
        PixelTrait splice_traits=GetPixelChannelTraits(splice_image,channel);
        if ((traits == UndefinedPixelTrait) ||
            (splice_traits == UndefinedPixelTrait))
          continue;
        SetPixelChannel(splice_image,channel,p[i],q);
      }
      SetPixelRed(splice_image,GetPixelRed(image,p),q);
      SetPixelGreen(splice_image,GetPixelGreen(image,p),q);
      SetPixelBlue(splice_image,GetPixelBlue(image,p),q);
      SetPixelAlpha(splice_image,GetPixelAlpha(image,p),q);
      p+=GetPixelChannels(image);
      q+=GetPixelChannels(splice_image);
    }
    if (SyncCacheViewAuthenticPixels(splice_view,exception) == MagickFalse)
      status=MagickFalse;
    if (image->progress_monitor != (MagickProgressMonitor) NULL)
      {
        MagickBooleanType
          proceed;

#if defined(MAGICKCORE_OPENMP_SUPPORT)
        #pragma omp critical (MagickCore_TransposeImage)
#endif
        proceed=SetImageProgress(image,SpliceImageTag,progress++,
          splice_image->rows);
        if (proceed == MagickFalse)
          status=MagickFalse;
      }
  }
#if defined(MAGICKCORE_OPENMP_SUPPORT)
  #pragma omp parallel for schedule(static,4) shared(progress,status) \
    magick_threads(image,splice_image,1,1)
#endif
  for (y=(ssize_t) (splice_geometry.y+splice_geometry.height);
       y < (ssize_t) splice_image->rows; y++)
  {
    register const Quantum
      *restrict p;

    register ssize_t
      x;

    register Quantum
      *restrict q;

    if (status == MagickFalse)
      continue;
    p=GetCacheViewVirtualPixels(image_view,0,y-(ssize_t) splice_geometry.height,
      image->columns,1,exception);
    if ((y < 0) || (y >= (ssize_t) splice_image->rows))
      continue;
    q=QueueCacheViewAuthenticPixels(splice_view,0,y,splice_image->columns,1,
      exception);
    if ((p == (const Quantum *) NULL) || (q == (Quantum *) NULL))
      {
        status=MagickFalse;
        continue;
      }
    for (x=0; x < splice_geometry.x; x++)
    {
      register ssize_t
        i;

      if (GetPixelReadMask(image,q) == 0)
        {
          SetPixelBackgoundColor(splice_image,q);
          p+=GetPixelChannels(image);
          q+=GetPixelChannels(splice_image);
          continue;
        }
      for (i=0; i < (ssize_t) GetPixelChannels(image); i++)
      {
        PixelChannel channel=GetPixelChannelChannel(image,i);
        PixelTrait traits=GetPixelChannelTraits(image,channel);
        PixelTrait splice_traits=GetPixelChannelTraits(splice_image,channel);
        if ((traits == UndefinedPixelTrait) ||
            (splice_traits == UndefinedPixelTrait))
          continue;
        SetPixelChannel(splice_image,channel,p[i],q);
      }
      SetPixelRed(splice_image,GetPixelRed(image,p),q);
      SetPixelGreen(splice_image,GetPixelGreen(image,p),q);
      SetPixelBlue(splice_image,GetPixelBlue(image,p),q);
      SetPixelAlpha(splice_image,GetPixelAlpha(image,p),q);
      p+=GetPixelChannels(image);
      q+=GetPixelChannels(splice_image);
    }
    for ( ; x < (ssize_t) (splice_geometry.x+splice_geometry.width); x++)
      q+=GetPixelChannels(splice_image);
    for ( ; x < (ssize_t) splice_image->columns; x++)
    {
      register ssize_t
        i;

      if (GetPixelReadMask(image,q) == 0)
        {
          SetPixelBackgoundColor(splice_image,q);
          p+=GetPixelChannels(image);
          q+=GetPixelChannels(splice_image);
          continue;
        }
      for (i=0; i < (ssize_t) GetPixelChannels(image); i++)
      {
        PixelChannel channel=GetPixelChannelChannel(image,i);
        PixelTrait traits=GetPixelChannelTraits(image,channel);
        PixelTrait splice_traits=GetPixelChannelTraits(splice_image,channel);
        if ((traits == UndefinedPixelTrait) ||
            (splice_traits == UndefinedPixelTrait))
          continue;
        SetPixelChannel(splice_image,channel,p[i],q);
      }
      SetPixelRed(splice_image,GetPixelRed(image,p),q);
      SetPixelGreen(splice_image,GetPixelGreen(image,p),q);
      SetPixelBlue(splice_image,GetPixelBlue(image,p),q);
      SetPixelAlpha(splice_image,GetPixelAlpha(image,p),q);
      p+=GetPixelChannels(image);
      q+=GetPixelChannels(splice_image);
    }
    if (SyncCacheViewAuthenticPixels(splice_view,exception) == MagickFalse)
      status=MagickFalse;
    if (image->progress_monitor != (MagickProgressMonitor) NULL)
      {
        MagickBooleanType
          proceed;

#if defined(MAGICKCORE_OPENMP_SUPPORT)
        #pragma omp critical (MagickCore_TransposeImage)
#endif
        proceed=SetImageProgress(image,SpliceImageTag,progress++,
          splice_image->rows);
        if (proceed == MagickFalse)
          status=MagickFalse;
      }
  }
  splice_view=DestroyCacheView(splice_view);
  image_view=DestroyCacheView(image_view);
  if (status == MagickFalse)
    splice_image=DestroyImage(splice_image);
  return(splice_image);
}
