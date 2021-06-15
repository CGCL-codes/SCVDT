static inline signed int ReadPropertyMSBLong(const unsigned char **p,
  size_t *length)
{
  union
  {
    unsigned int
      unsigned_value;

    signed int
      signed_value;
  } quantum;

  int
    c;

  register ssize_t
    i;

  unsigned char
    buffer[4];

  unsigned int
    value;

  if (*length < 4)
    return(-1);
  for (i=0; i < 4; i++)
  {
    c=(int) (*(*p)++);
    (*length)--;
    buffer[i]=(unsigned char) c;
  }
  value=(unsigned int) buffer[0] << 24;
  value|=(unsigned int) buffer[1] << 16;
  value|=(unsigned int) buffer[2] << 8;
  value|=(unsigned int) buffer[3];
  quantum.unsigned_value=value & 0xffffffff;
  return(quantum.signed_value);
}
