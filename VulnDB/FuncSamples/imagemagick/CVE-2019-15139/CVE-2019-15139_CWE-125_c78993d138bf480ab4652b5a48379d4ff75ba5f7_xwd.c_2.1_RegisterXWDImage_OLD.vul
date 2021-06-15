ModuleExport size_t RegisterXWDImage(void)
{
  MagickInfo
    *entry;

  entry=AcquireMagickInfo("XWD","XWD","X Windows system window dump (color)");
#if defined(MAGICKCORE_X11_DELEGATE)
  entry->decoder=(DecodeImageHandler *) ReadXWDImage;
  entry->encoder=(EncodeImageHandler *) WriteXWDImage;
#endif
  entry->magick=(IsImageFormatHandler *) IsXWD;
  entry->flags^=CoderAdjoinFlag;
  (void) RegisterMagickInfo(entry);
  return(MagickImageCoderSignature);
}
