static MagickBooleanType Get8BIMProperty(const Image *image,const char *key,
  ExceptionInfo *exception)
{
  char
    *attribute,
    format[MagickPathExtent],
    name[MagickPathExtent],
    *resource;

  const StringInfo
    *profile;

  const unsigned char
    *info;

  long
    start,
    stop;

  MagickBooleanType
    status;

  register ssize_t
    i;

  size_t
    length;

  ssize_t
    count,
    id,
    sub_number;

  /*
    There are no newlines in path names, so it's safe as terminator.
  */
  profile=GetImageProfile(image,"8bim");
  if (profile == (StringInfo *) NULL)
    return(MagickFalse);
  count=(ssize_t) sscanf(key,"8BIM:%ld,%ld:%1024[^\n]\n%1024[^\n]",&start,&stop,
    name,format);
  if ((count != 2) && (count != 3) && (count != 4))
    return(MagickFalse);
  if (count < 4)
    (void) CopyMagickString(format,"SVG",MagickPathExtent);
  if (count < 3)
    *name='\0';
  sub_number=1;
  if (*name == '#')
    sub_number=(ssize_t) StringToLong(&name[1]);
  sub_number=MagickMax(sub_number,1L);
  resource=(char *) NULL;
  status=MagickFalse;
  length=GetStringInfoLength(profile);
  info=GetStringInfoDatum(profile);
  while ((length > 0) && (status == MagickFalse))
  {
    if (ReadPropertyByte(&info,&length) != (unsigned char) '8')
      continue;
    if (ReadPropertyByte(&info,&length) != (unsigned char) 'B')
      continue;
    if (ReadPropertyByte(&info,&length) != (unsigned char) 'I')
      continue;
    if (ReadPropertyByte(&info,&length) != (unsigned char) 'M')
      continue;
    id=(ssize_t) ReadPropertyMSBShort(&info,&length);
    if (id < (ssize_t) start)
      continue;
    if (id > (ssize_t) stop)
      continue;
    if (resource != (char *) NULL)
      resource=DestroyString(resource);
    count=(ssize_t) ReadPropertyByte(&info,&length);
    if ((count != 0) && ((size_t) count <= length))
      {
        resource=(char *) NULL;
        if (~((size_t) count) >= (MagickPathExtent-1))
          resource=(char *) AcquireQuantumMemory((size_t) count+
            MagickPathExtent,sizeof(*resource));
        if (resource != (char *) NULL)
          {
            for (i=0; i < (ssize_t) count; i++)
              resource[i]=(char) ReadPropertyByte(&info,&length);
            resource[count]='\0';
          }
      }
    if ((count & 0x01) == 0)
      (void) ReadPropertyByte(&info,&length);
    count=(ssize_t) ReadPropertyMSBLong(&info,&length);
    if ((count < 0) || ((size_t) count > length))
      {
        length=0; 
        continue;
      }
    if ((*name != '\0') && (*name != '#'))
      if ((resource == (char *) NULL) || (LocaleCompare(name,resource) != 0))
        {
          /*
            No name match, scroll forward and try next.
          */
          info+=count;
          length-=MagickMin(count,(ssize_t) length);
          continue;
        }
    if ((*name == '#') && (sub_number != 1))
      {
        /*
          No numbered match, scroll forward and try next.
        */
        sub_number--;
        info+=count;
        length-=MagickMin(count,(ssize_t) length);
        continue;
      }
    /*
      We have the resource of interest.
    */
    attribute=(char *) NULL;
    if (~((size_t) count) >= (MagickPathExtent-1))
      attribute=(char *) AcquireQuantumMemory((size_t) count+MagickPathExtent,
        sizeof(*attribute));
    if (attribute != (char *) NULL)
      {
        (void) CopyMagickMemory(attribute,(char *) info,(size_t) count);
        attribute[count]='\0';
        info+=count;
        length-=MagickMin(count,(ssize_t) length);
        if ((id <= 1999) || (id >= 2999))
          (void) SetImageProperty((Image *) image,key,(const char *)
            attribute,exception);
        else
          {
            char
              *path;

            if (LocaleCompare(format,"svg") == 0)
              path=TraceSVGClippath((unsigned char *) attribute,(size_t) count,
                image->columns,image->rows);
            else
              path=TracePSClippath((unsigned char *) attribute,(size_t) count);
            (void) SetImageProperty((Image *) image,key,(const char *) path,
              exception);
            path=DestroyString(path);
          }
        attribute=DestroyString(attribute);
        status=MagickTrue;
      }
  }
  if (resource != (char *) NULL)
    resource=DestroyString(resource);
  return(status);
}
