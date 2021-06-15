static MagickOffsetType TIFFSeekCustomStream(const MagickOffsetType offset,
  const int whence,void *user_data)
{
  PhotoshopProfile
    *profile;

  profile=(PhotoshopProfile *) user_data;
  switch (whence)
  {
    case SEEK_SET:
    default:
    {
      if (offset < 0)
        return(-1);
      profile->offset=offset;
      break;
    }
    case SEEK_CUR:
    {
      if ((profile->offset+offset) < 0)
        return(-1);
      profile->offset+=offset;
      break;
    }
    case SEEK_END:
    {
      if (((MagickOffsetType) profile->length+offset) < 0)
        return(-1);
      profile->offset=profile->length+offset;
      break;
    }
  }

  return(profile->offset);
}
