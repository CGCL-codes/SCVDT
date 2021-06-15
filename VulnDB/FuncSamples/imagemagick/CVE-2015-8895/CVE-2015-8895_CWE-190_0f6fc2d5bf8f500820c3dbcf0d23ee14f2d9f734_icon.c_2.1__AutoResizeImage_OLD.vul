Image *AutoResizeImage(const Image *image,const char *option,
  MagickOffsetType *count,ExceptionInfo *exception)
{
  #define MAX_SIZES 16

  char
    *q;

  const char
    *p;

  Image
    *resized,
    *images;

  register ssize_t
    i;

  size_t
    sizes[MAX_SIZES]={256,192,128,96,64,48,40,32,24,16};

  images=NULL;
  *count=0;
  i=0;
  p=option;
  while (*p != '\0' && i < MAX_SIZES)
  {
    size_t
      size;

    while ((isspace((int) ((unsigned char) *p)) != 0))
      p++;

    size=(size_t)strtol(p,&q,10);
    if (p == q || size < 16 || size > 256)
        return((Image *) NULL);

    p=q;
    sizes[i++]=size;

    while ((isspace((int) ((unsigned char) *p)) != 0) || (*p == ','))
      p++;
  }

  if (i==0)
    i=10;
  *count=i;
  for (i=0; i < *count; i++)
  {
    resized=ResizeImage(image,sizes[i],sizes[i],image->filter,exception);
    if (resized == (Image *) NULL)
      return(DestroyImageList(images));

    if (images == (Image *) NULL)
      images=resized;
    else
      AppendImageToList(&images,resized);
  }
  return(images);
}
