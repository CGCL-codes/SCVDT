static ssize_t DecodePSDPixels(const size_t number_compact_pixels,
  const unsigned char *compact_pixels,const ssize_t depth,
  const size_t number_pixels,unsigned char *pixels)
{
#define CheckNumberCompactPixels \
  if (packets == 0) \
    return(i); \
  packets--

#define CheckNumberPixels(count) \
  if (((ssize_t) i + count) > (ssize_t) number_pixels) \
    return(i); \
  i+=count

  int
    pixel;

  register ssize_t
    i,
    j;

  size_t
    length;

  ssize_t
    packets;

  packets=(ssize_t) number_compact_pixels;
  for (i=0; (packets > 1) && (i < (ssize_t) number_pixels); )
  {
    packets--;
    length=(size_t) (*compact_pixels++);
    if (length == 128)
      continue;
    if (length > 128)
      {
        length=256-length+1;
        CheckNumberCompactPixels;
        pixel=(*compact_pixels++);
        for (j=0; j < (ssize_t) length; j++)
        {
          switch (depth)
          {
            case 1:
            {
              CheckNumberPixels(8);
              *pixels++=(pixel >> 7) & 0x01 ? 0U : 255U;
              *pixels++=(pixel >> 6) & 0x01 ? 0U : 255U;
              *pixels++=(pixel >> 5) & 0x01 ? 0U : 255U;
              *pixels++=(pixel >> 4) & 0x01 ? 0U : 255U;
              *pixels++=(pixel >> 3) & 0x01 ? 0U : 255U;
              *pixels++=(pixel >> 2) & 0x01 ? 0U : 255U;
              *pixels++=(pixel >> 1) & 0x01 ? 0U : 255U;
              *pixels++=(pixel >> 0) & 0x01 ? 0U : 255U;
              break;
            }
            case 2:
            {
              CheckNumberPixels(4);
              *pixels++=(unsigned char) ((pixel >> 6) & 0x03);
              *pixels++=(unsigned char) ((pixel >> 4) & 0x03);
              *pixels++=(unsigned char) ((pixel >> 2) & 0x03);
              *pixels++=(unsigned char) ((pixel & 0x03) & 0x03);
              break;
            }
            case 4:
            {
              CheckNumberPixels(2);
              *pixels++=(unsigned char) ((pixel >> 4) & 0xff);
              *pixels++=(unsigned char) ((pixel & 0x0f) & 0xff);
              break;
            }
            default:
            {
              CheckNumberPixels(1);
              *pixels++=(unsigned char) pixel;
              break;
            }
          }
        }
        continue;
      }
    length++;
    for (j=0; j < (ssize_t) length; j++)
    {
      switch (depth)
      {
        case 1:
        {
          CheckNumberPixels(8);
          *pixels++=(*compact_pixels >> 7) & 0x01 ? 0U : 255U;
          *pixels++=(*compact_pixels >> 6) & 0x01 ? 0U : 255U;
          *pixels++=(*compact_pixels >> 5) & 0x01 ? 0U : 255U;
          *pixels++=(*compact_pixels >> 4) & 0x01 ? 0U : 255U;
          *pixels++=(*compact_pixels >> 3) & 0x01 ? 0U : 255U;
          *pixels++=(*compact_pixels >> 2) & 0x01 ? 0U : 255U;
          *pixels++=(*compact_pixels >> 1) & 0x01 ? 0U : 255U;
          *pixels++=(*compact_pixels >> 0) & 0x01 ? 0U : 255U;
          break;
        }
        case 2:
        {
          CheckNumberPixels(4);
          *pixels++=(*compact_pixels >> 6) & 0x03;
          *pixels++=(*compact_pixels >> 4) & 0x03;
          *pixels++=(*compact_pixels >> 2) & 0x03;
          *pixels++=(*compact_pixels & 0x03) & 0x03;
          break;
        }
        case 4:
        {
          CheckNumberPixels(2);
          *pixels++=(*compact_pixels >> 4) & 0xff;
          *pixels++=(*compact_pixels & 0x0f) & 0xff;
          break;
        }
        default:
        {
          CheckNumberPixels(1);
          *pixels++=(*compact_pixels);
          break;
        }
      }
      CheckNumberCompactPixels;
      compact_pixels++;
    }
  }
  return(i);
}
