static void
cpTags(TIFF* in, TIFF* out)
{
    struct cpTag *p;
    for (p = tags; p < &tags[NTAGS]; p++)
	cpTag(in, out, p->tag, p->count, p->type);
}
