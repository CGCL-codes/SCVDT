static inline size_t GetPSDRowSize(Image *image)
{
  if (image->depth == 1)
    return((image->columns+7)/8);
  else
    return(image->columns*GetPSDPacketSize(image));
}
