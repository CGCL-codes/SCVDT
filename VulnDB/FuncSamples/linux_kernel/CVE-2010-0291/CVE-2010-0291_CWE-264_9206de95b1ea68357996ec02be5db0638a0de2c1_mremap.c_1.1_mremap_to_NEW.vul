static unsigned long mremap_to(unsigned long addr,
	unsigned long old_len, unsigned long new_addr,
	unsigned long new_len)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long ret = -EINVAL;
	unsigned long charged = 0;
	unsigned long map_flags;

	if (new_addr & ~PAGE_MASK)
		goto out;

	if (new_len > TASK_SIZE || new_addr > TASK_SIZE - new_len)
		goto out;

	/* Check if the location we're moving into overlaps the
	 * old location at all, and fail if it does.
	 */
	if ((new_addr <= addr) && (new_addr+new_len) > addr)
		goto out;

	if ((addr <= new_addr) && (addr+old_len) > new_addr)
		goto out;

	ret = security_file_mmap(NULL, 0, 0, 0, new_addr, 1);
	if (ret)
		goto out;

	ret = do_munmap(mm, new_addr, new_len);
	if (ret)
		goto out;

	if (old_len >= new_len) {
		ret = do_munmap(mm, addr+new_len, old_len - new_len);
		if (ret && old_len != new_len)
			goto out;
		old_len = new_len;
	}

	vma = vma_to_resize(addr, old_len, new_len, &charged);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto out;
	}

	map_flags = MAP_FIXED;
	if (vma->vm_flags & VM_MAYSHARE)
		map_flags |= MAP_SHARED;

	ret = get_unmapped_area(vma->vm_file, new_addr, new_len, vma->vm_pgoff +
				((addr - vma->vm_start) >> PAGE_SHIFT),
				map_flags);
	if (ret & ~PAGE_MASK)
		goto out1;

	ret = move_vma(vma, addr, old_len, new_len, new_addr);
	if (!(ret & ~PAGE_MASK))
		goto out;
out1:
	vm_unacct_memory(charged);

out:
	return ret;
}
