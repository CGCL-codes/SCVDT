static MagickBooleanType TIFFWritePhotoshopLayers(Image* image,
  const ImageInfo *image_info,EndianType endian,ExceptionInfo *exception)
{
  BlobInfo
    *blob;

  CustomStreamInfo
    *custom_stream;

  Image
    *base_image,
    *next;

  ImageInfo
    *clone_info;

  MagickBooleanType
    status;

  PhotoshopProfile
    profile;

  PSDInfo
    info;

  StringInfo
    *layers;

  base_image=CloneImage(image,0,0,MagickFalse,exception);
  if (base_image == (Image *) NULL)
    return(MagickTrue);
  clone_info=CloneImageInfo(image_info);
  if (clone_info == (ImageInfo *) NULL)
    ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
      image->filename);
  profile.offset=0;
  profile.quantum=MagickMinBlobExtent;
  layers=AcquireStringInfo(profile.quantum);
  if (layers == (StringInfo *) NULL)
    {
      base_image=DestroyImage(base_image);
      clone_info=DestroyImageInfo(clone_info);
      ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
        image->filename);
    }
  profile.data=layers;
  profile.extent=layers->length;
  custom_stream=TIFFAcquireCustomStreamForWriting(&profile,exception);
  if (custom_stream == (CustomStreamInfo *) NULL)
    {
      base_image=DestroyImage(base_image);
      clone_info=DestroyImageInfo(clone_info);
      layers=DestroyStringInfo(layers);
      ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
        image->filename);
    }
  blob=CloneBlobInfo((BlobInfo *) NULL);
  if (blob == (BlobInfo *) NULL)
    {
      base_image=DestroyImage(base_image);
      clone_info=DestroyImageInfo(clone_info);
      layers=DestroyStringInfo(layers);
      custom_stream=DestroyCustomStreamInfo(custom_stream);
      ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
        image->filename);
    }
  DestroyBlob(base_image);
  base_image->blob=blob;
  next=base_image;
  while (next != (Image *) NULL)
    next=SyncNextImageInList(next);
  AttachCustomStream(base_image->blob,custom_stream);
  InitPSDInfo(image,&info);
  base_image->endian=endian;
  WriteBlobString(base_image,"Adobe Photoshop Document Data Block");
  WriteBlobByte(base_image,0);
  WriteBlobString(base_image,base_image->endian == LSBEndian ? "MIB8ryaL" :
    "8BIMLayr");
  status=WritePSDLayers(base_image,clone_info,&info,exception);
  if (status != MagickFalse)
    {
      SetStringInfoLength(layers,(size_t) profile.offset);
      status=SetImageProfile(image,"tiff:37724",layers,exception);
    }
  next=base_image;
  while (next != (Image *) NULL)
  {
    CloseBlob(next);
    next=next->next;
  }
  layers=DestroyStringInfo(layers);
  clone_info=DestroyImageInfo(clone_info);
  custom_stream=DestroyCustomStreamInfo(custom_stream);
  return(status);
}
