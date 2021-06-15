static pfn_t kvm_pin_pages(struct kvm_memory_slot *slot, gfn_t gfn,
			   unsigned long npages)
{
	gfn_t end_gfn;
	pfn_t pfn;

	pfn     = gfn_to_pfn_memslot(slot, gfn);
	end_gfn = gfn + npages;
	gfn    += 1;

	if (is_error_noslot_pfn(pfn))
		return pfn;

	while (gfn < end_gfn)
		gfn_to_pfn_memslot(slot, gfn++);

	return pfn;
}
