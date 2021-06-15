static void
videobuf_vm_open(struct vm_area_struct *vma)
{
	struct videobuf_mapping *map = vma->vm_private_data;

	dprintk(2,"vm_open %p [count=%d,vma=%08lx-%08lx]\n",map,
		map->count,vma->vm_start,vma->vm_end);

	map->count++;
}
