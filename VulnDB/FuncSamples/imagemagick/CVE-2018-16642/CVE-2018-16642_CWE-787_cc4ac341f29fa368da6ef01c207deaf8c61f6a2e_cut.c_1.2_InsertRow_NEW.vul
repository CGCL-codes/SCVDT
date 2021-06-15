static MagickBooleanType InsertRow(Image *image,ssize_t bpp,unsigned char *p,
  ssize_t y,ExceptionInfo *exception)
{
  int
    bit;

  Quantum
    index;

  register Quantum
    *q;

  ssize_t
    x;

  q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
  if (q == (Quantum *) NULL)
    return(MagickFalse);
  switch (bpp)
    {
    case 1:  /* Convert bitmap scanline. */
      {
        for (x=0; x < ((ssize_t) image->columns-7); x+=8)
        {
          for (bit=0; bit < 8; bit++)
          {
            index=((*p) & (0x80 >> bit) ? 0x01 : 0x00);
            SetPixelIndex(image,index,q);
            if (index < image->colors)
              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
            q+=GetPixelChannels(image);
          }
          p++;
        }
        if ((image->columns % 8) != 0)
          {
            for (bit=0; bit < (ssize_t) (image->columns % 8); bit++)
            {
              index=((*p) & (0x80 >> bit) ? 0x01 : 0x00);
              SetPixelIndex(image,index,q);
              if (index < image->colors)
                SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
              q+=GetPixelChannels(image);
            }
            p++;
          }
        break;
      }
    case 2:  /* Convert PseudoColor scanline. */
      {
        for (x=0; x < ((ssize_t) image->columns-3); x+=4)
        {
            index=ConstrainColormapIndex(image,(*p >> 6) & 0x3,exception);
            SetPixelIndex(image,index,q);
            if (index < image->colors)
              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
            q+=GetPixelChannels(image);
            index=ConstrainColormapIndex(image,(*p >> 4) & 0x3,exception);
            SetPixelIndex(image,index,q);
            if (index < image->colors)
              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
            q+=GetPixelChannels(image);
            index=ConstrainColormapIndex(image,(*p >> 2) & 0x3,exception);
            SetPixelIndex(image,index,q);
            if (index < image->colors)
              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
            q+=GetPixelChannels(image);
            index=ConstrainColormapIndex(image,(*p) & 0x3,exception);
            SetPixelIndex(image,index,q);
            if (index < image->colors)
              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
            q+=GetPixelChannels(image);
            p++;
        }
       if ((image->columns % 4) != 0)
          {
            index=ConstrainColormapIndex(image,(*p >> 6) & 0x3,exception);
            SetPixelIndex(image,index,q);
            if (index < image->colors)
              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
            q+=GetPixelChannels(image);
            if ((image->columns % 4) > 1)
              {
                index=ConstrainColormapIndex(image,(*p >> 4) & 0x3,exception);
                SetPixelIndex(image,index,q);
                if (index < image->colors)
                  SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
                q+=GetPixelChannels(image);
                if ((image->columns % 4) > 2)
                  {
                    index=ConstrainColormapIndex(image,(*p >> 2) & 0x3,
                      exception);
                    SetPixelIndex(image,index,q);
                    if (index < image->colors)
                      SetPixelViaPixelInfo(image,image->colormap+(ssize_t)
                        index,q);
                    q+=GetPixelChannels(image);
                  }
              }
            p++;
          }
        break;
      }

    case 4:  /* Convert PseudoColor scanline. */
      {
        for (x=0; x < ((ssize_t) image->columns-1); x+=2)
          {
            index=ConstrainColormapIndex(image,(*p >> 4) & 0x0f,exception);
            SetPixelIndex(image,index,q);
            if (index < image->colors)
              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
            q+=GetPixelChannels(image);
            index=ConstrainColormapIndex(image,(*p) & 0x0f,exception);
            SetPixelIndex(image,index,q);
            if (index < image->colors)
              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
            p++;
            q+=GetPixelChannels(image);
          }
        if ((image->columns % 2) != 0)
          {
            index=ConstrainColormapIndex(image,(*p >> 4) & 0x0f,exception);
            SetPixelIndex(image,index,q);
            if (index < image->colors)
              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
            p++;
            q+=GetPixelChannels(image);
          }
        break;
      }
    case 8: /* Convert PseudoColor scanline. */
      {
        for (x=0; x < (ssize_t) image->columns; x++)
          {
            index=ConstrainColormapIndex(image,*p,exception);
            SetPixelIndex(image,index,q);
            if (index < image->colors)
              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
            p++;
            q+=GetPixelChannels(image);
          }
      }
      break;

    case 24:     /*  Convert DirectColor scanline.  */
      for (x=0; x < (ssize_t) image->columns; x++)
        {
          SetPixelRed(image,ScaleCharToQuantum(*p++),q);
          SetPixelGreen(image,ScaleCharToQuantum(*p++),q);
          SetPixelBlue(image,ScaleCharToQuantum(*p++),q);
          q+=GetPixelChannels(image);
        }
      break;
    }
  if (!SyncAuthenticPixels(image,exception))
    return(MagickFalse);
  return(MagickTrue);
}
