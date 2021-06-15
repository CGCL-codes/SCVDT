static inline signed short ReadPropertyMSBShort(const unsigned char **p,
  size_t *length)
{
  union
  {
    unsigned short
      unsigned_value;

    signed short
      signed_value;
  } quantum;

  int
    c;

  register ssize_t
    i;

  unsigned char
    buffer[2];

  unsigned short
    value;

  if (*length < 2)
    return((unsigned short) ~0);
  for (i=0; i < 2; i++)
  {
    c=(int) (*(*p)++);
    (*length)--;
    buffer[i]=(unsigned char) c;
  }
  value=(unsigned short) buffer[0] << 8;
  value|=(unsigned short) buffer[1];
  quantum.unsigned_value=value & 0xffff;
  return(quantum.signed_value);
}
