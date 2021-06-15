static int __videobuf_mmap_mapper(struct videobuf_queue *q,
			 struct vm_area_struct *vma)
{
	struct videbuf_vmalloc_memory *mem;
	struct videobuf_mapping *map;
	unsigned int first;
	int retval;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;

	if (! (vma->vm_flags & VM_WRITE) || ! (vma->vm_flags & VM_SHARED))
		return -EINVAL;

	/* look for first buffer to map */
	for (first = 0; first < VIDEO_MAX_FRAME; first++) {
		if (NULL == q->bufs[first])
			continue;

		if (V4L2_MEMORY_MMAP != q->bufs[first]->memory)
			continue;
		if (q->bufs[first]->boff == offset)
			break;
	}
	if (VIDEO_MAX_FRAME == first) {
		dprintk(1,"mmap app bug: offset invalid [offset=0x%lx]\n",
			(vma->vm_pgoff << PAGE_SHIFT));
		return -EINVAL;
	}

	/* create mapping + update buffer list */
	map = q->bufs[first]->map = kzalloc(sizeof(struct videobuf_mapping),GFP_KERNEL);
	if (NULL == map)
		return -ENOMEM;

	map->start = vma->vm_start;
	map->end   = vma->vm_end;
	map->q     = q;

	q->bufs[first]->baddr = vma->vm_start;

	vma->vm_ops          = &videobuf_vm_ops;
	vma->vm_flags       |= VM_DONTEXPAND | VM_RESERVED;
	vma->vm_private_data = map;

	mem=q->bufs[first]->priv;
	BUG_ON (!mem);
	MAGIC_CHECK(mem->magic,MAGIC_VMAL_MEM);

	/* Try to remap memory */
	retval=remap_vmalloc_range(vma, mem->vmalloc,0);
	if (retval<0) {
		dprintk(1,"mmap: postponing remap_vmalloc_range\n");

		mem->vma=kmalloc(sizeof(*vma),GFP_KERNEL);
		if (!mem->vma) {
			kfree(map);
			q->bufs[first]->map=NULL;
			return -ENOMEM;
		}
		memcpy(mem->vma,vma,sizeof(*vma));
	}

	dprintk(1,"mmap %p: q=%p %08lx-%08lx (%lx) pgoff %08lx buf %d\n",
		map,q,vma->vm_start,vma->vm_end,
		(long int) q->bufs[first]->bsize,
		vma->vm_pgoff,first);

	videobuf_vm_open(vma);

	return (0);
}
