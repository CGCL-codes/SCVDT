int mem_check_range(struct rxe_mem *mem, u64 iova, size_t length)
{
	switch (mem->type) {
	case RXE_MEM_TYPE_DMA:
		return 0;

	case RXE_MEM_TYPE_MR:
	case RXE_MEM_TYPE_FMR:
		return ((iova < mem->iova) ||
			((iova + length) > (mem->iova + mem->length))) ?
			-EFAULT : 0;

	default:
		return -EFAULT;
	}
}
