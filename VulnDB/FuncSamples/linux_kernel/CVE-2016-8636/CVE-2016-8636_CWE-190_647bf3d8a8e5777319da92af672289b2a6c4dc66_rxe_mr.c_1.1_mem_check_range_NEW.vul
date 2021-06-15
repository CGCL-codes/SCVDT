int mem_check_range(struct rxe_mem *mem, u64 iova, size_t length)
{
	switch (mem->type) {
	case RXE_MEM_TYPE_DMA:
		return 0;

	case RXE_MEM_TYPE_MR:
	case RXE_MEM_TYPE_FMR:
		if (iova < mem->iova ||
		    length > mem->length ||
		    iova > mem->iova + mem->length - length)
			return -EFAULT;
		return 0;

	default:
		return -EFAULT;
	}
}
