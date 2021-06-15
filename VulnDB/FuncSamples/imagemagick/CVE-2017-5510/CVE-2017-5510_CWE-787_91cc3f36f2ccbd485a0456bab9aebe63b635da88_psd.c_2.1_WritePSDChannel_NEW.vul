static size_t WritePSDChannel(const PSDInfo *psd_info,
  const ImageInfo *image_info,Image *image,Image *next_image,
  const QuantumType quantum_type, unsigned char *compact_pixels,
  MagickOffsetType size_offset,const MagickBooleanType separate,
  ExceptionInfo *exception)
{
  int
    y;

  MagickBooleanType
    monochrome;

  QuantumInfo
    *quantum_info;

  register const Quantum
    *p;

  register ssize_t
    i;

  size_t
    count,
    length;

  unsigned char
    *pixels;

#ifdef MAGICKCORE_ZLIB_DELEGATE

#define CHUNK 16384

  int
    flush,
    level;

  unsigned char
    *compressed_pixels;

  z_stream
    stream;

  compressed_pixels=(unsigned char *) NULL;
  flush=Z_NO_FLUSH;
#endif
  count=0;
  if (separate != MagickFalse)
    {
      size_offset=TellBlob(image)+2;
      count+=WriteCompressionStart(psd_info,image,next_image,1);
    }
  if (next_image->depth > 8)
    next_image->depth=16;
  monochrome=IsImageMonochrome(image) && (image->depth == 1) ?
    MagickTrue : MagickFalse;
  quantum_info=AcquireQuantumInfo(image_info,next_image);
  if (quantum_info == (QuantumInfo *) NULL)
    return(0);
  pixels=(unsigned char *) GetQuantumPixels(quantum_info);
#ifdef MAGICKCORE_ZLIB_DELEGATE
  if (next_image->compression == ZipCompression)
    {
      compressed_pixels=(unsigned char *) AcquireQuantumMemory(CHUNK,
        sizeof(*compressed_pixels));
      if (compressed_pixels == (unsigned char *) NULL)
        {
          quantum_info=DestroyQuantumInfo(quantum_info);
          return(0);
        }
      ResetMagickMemory(&stream,0,sizeof(stream));
      stream.data_type=Z_BINARY;
      level=Z_DEFAULT_COMPRESSION;
      if ((image_info->quality > 0 && image_info->quality < 10))
        level=(int) image_info->quality;
      if (deflateInit(&stream,level) != Z_OK)
        {
          quantum_info=DestroyQuantumInfo(quantum_info);
          return(0);
        }
    }
#endif
  for (y=0; y < (ssize_t) next_image->rows; y++)
  {
    p=GetVirtualPixels(next_image,0,y,next_image->columns,1,exception);
    if (p == (const Quantum *) NULL)
      break;
    length=ExportQuantumPixels(next_image,(CacheView *) NULL,quantum_info,
      quantum_type,pixels,exception);
    if (monochrome != MagickFalse)
      for (i=0; i < (ssize_t) length; i++)
        pixels[i]=(~pixels[i]);
    if (next_image->compression == RLECompression)
      {
        length=PSDPackbitsEncodeImage(image,length,pixels,compact_pixels,
          exception);
        count+=WriteBlob(image,length,compact_pixels);
        size_offset+=WritePSDOffset(psd_info,image,length,size_offset);
      }
#ifdef MAGICKCORE_ZLIB_DELEGATE
    else if (next_image->compression == ZipCompression)
      {
        stream.avail_in=(uInt) length;
        stream.next_in=(Bytef *) pixels;
        if (y == (ssize_t) next_image->rows-1)
          flush=Z_FINISH;
        do {
            stream.avail_out=(uInt) CHUNK;
            stream.next_out=(Bytef *) compressed_pixels;
            if (deflate(&stream,flush) == Z_STREAM_ERROR)
              break;
            length=(size_t) CHUNK-stream.avail_out;
            if (length > 0)
              count+=WriteBlob(image,length,compressed_pixels);
        } while (stream.avail_out == 0);
      }
#endif
    else
      count+=WriteBlob(image,length,pixels);
  }
#ifdef MAGICKCORE_ZLIB_DELEGATE
  if (next_image->compression == ZipCompression)
    {
      (void) deflateEnd(&stream);
      compressed_pixels=(unsigned char *) RelinquishMagickMemory(
        compressed_pixels);
    }
#endif
  quantum_info=DestroyQuantumInfo(quantum_info);
  return(count);
}
