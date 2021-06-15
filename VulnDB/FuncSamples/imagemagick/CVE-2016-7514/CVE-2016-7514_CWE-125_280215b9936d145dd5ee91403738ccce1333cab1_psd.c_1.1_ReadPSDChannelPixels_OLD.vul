static MagickBooleanType ReadPSDChannelPixels(Image *image,
  const size_t channels,const size_t row,const ssize_t type,
  const unsigned char *pixels,ExceptionInfo *exception)
{
  Quantum
    pixel;

  register const unsigned char
    *p;

  register Quantum
    *q;

  register ssize_t
    x;

  size_t
    packet_size;

  unsigned short
    nibble;

  p=pixels;
  q=GetAuthenticPixels(image,0,row,image->columns,1,exception);
  if (q == (Quantum *) NULL)
    return MagickFalse;
  packet_size=GetPSDPacketSize(image);
  for (x=0; x < (ssize_t) image->columns; x++)
  {
    if (packet_size == 1)
      pixel=ScaleCharToQuantum(*p++);
    else
      {
        p=PushShortPixel(MSBEndian,p,&nibble);
        pixel=ScaleShortToQuantum(nibble);
      }
    switch (type)
    {
      case -1:
      {
        SetPixelAlpha(image,pixel,q);
        break;
      }
      case -2:
      case 0:
      {
        SetPixelRed(image,pixel,q);
        if (channels == 1 || type == -2)
          SetPixelGray(image,pixel,q);
        if (image->storage_class == PseudoClass)
          {
            if (packet_size == 1)
              SetPixelIndex(image,ScaleQuantumToChar(pixel),q);
            else
              SetPixelIndex(image,ScaleQuantumToShort(pixel),q);
            SetPixelViaPixelInfo(image,image->colormap+(ssize_t)
              ConstrainColormapIndex(image,GetPixelIndex(image,q),exception),q);
            if (image->depth == 1)
              {
                ssize_t
                  bit,
                  number_bits;
  
                number_bits=image->columns-x;
                if (number_bits > 8)
                  number_bits=8;
                for (bit=0; bit < number_bits; bit++)
                {
                  SetPixelIndex(image,(((unsigned char) pixel) &
                    (0x01 << (7-bit))) != 0 ? 0 : 255,q);
                  SetPixelViaPixelInfo(image,image->colormap+(ssize_t)
                    ConstrainColormapIndex(image,GetPixelIndex(image,q),
                      exception),q);
                  q+=GetPixelChannels(image);
                  x++;
                }
                x--;
                continue;
              }
          }
        break;
      }
      case 1:
      {
        if (image->storage_class == PseudoClass)
          SetPixelAlpha(image,pixel,q);
        else
          SetPixelGreen(image,pixel,q);
        break;
      }
      case 2:
      {
        if (image->storage_class == PseudoClass)
          SetPixelAlpha(image,pixel,q);
        else
          SetPixelBlue(image,pixel,q);
        break;
      }
      case 3:
      {
        if (image->colorspace == CMYKColorspace)
          SetPixelBlack(image,pixel,q);
        else
          if (image->alpha_trait != UndefinedPixelTrait)
            SetPixelAlpha(image,pixel,q);
        break;
      }
      case 4:
      {
        if ((IssRGBCompatibleColorspace(image->colorspace) != MagickFalse) &&
            (channels > 3))
          break;
        if (image->alpha_trait != UndefinedPixelTrait)
          SetPixelAlpha(image,pixel,q);
        break;
      }
      default:
        break;
    }
    q+=GetPixelChannels(image);
  }
  return(SyncAuthenticPixels(image,exception));
}
