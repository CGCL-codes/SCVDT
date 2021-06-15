static inline unsigned short ReadPropertyUnsignedShort(const EndianType endian,
  const unsigned char *buffer)
{
  unsigned short
    value;

  if (endian == LSBEndian)
    {
      value=(unsigned short) buffer[1] << 8;
      value|=(unsigned short) buffer[0];
      return(value & 0xffff);
    }
  value=(unsigned short) buffer[0] << 8;
  value|=(unsigned short) buffer[1];
  return(value & 0xffff);
}
