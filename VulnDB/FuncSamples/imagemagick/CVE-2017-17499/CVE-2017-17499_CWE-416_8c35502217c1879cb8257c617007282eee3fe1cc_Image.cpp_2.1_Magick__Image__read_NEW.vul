void Magick::Image::read(const Blob &blob_)
{
  MagickCore::Image
    *newImage;

  GetPPException;
  newImage=BlobToImage(imageInfo(),static_cast<const void *>(blob_.data()),
    blob_.length(),exceptionInfo);
  read(newImage,exceptionInfo);
}
