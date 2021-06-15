int kvm_iommu_map_pages(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	gfn_t gfn, end_gfn;
	pfn_t pfn;
	int r = 0;
	struct iommu_domain *domain = kvm->arch.iommu_domain;
	int flags;

	/* check if iommu exists and in use */
	if (!domain)
		return 0;

	gfn     = slot->base_gfn;
	end_gfn = gfn + slot->npages;

	flags = IOMMU_READ;
	if (!(slot->flags & KVM_MEM_READONLY))
		flags |= IOMMU_WRITE;
	if (!kvm->arch.iommu_noncoherent)
		flags |= IOMMU_CACHE;


	while (gfn < end_gfn) {
		unsigned long page_size;

		/* Check if already mapped */
		if (iommu_iova_to_phys(domain, gfn_to_gpa(gfn))) {
			gfn += 1;
			continue;
		}

		/* Get the page size we could use to map */
		page_size = kvm_host_page_size(kvm, gfn);

		/* Make sure the page_size does not exceed the memslot */
		while ((gfn + (page_size >> PAGE_SHIFT)) > end_gfn)
			page_size >>= 1;

		/* Make sure gfn is aligned to the page size we want to map */
		while ((gfn << PAGE_SHIFT) & (page_size - 1))
			page_size >>= 1;

		/* Make sure hva is aligned to the page size we want to map */
		while (__gfn_to_hva_memslot(slot, gfn) & (page_size - 1))
			page_size >>= 1;

		/*
		 * Pin all pages we are about to map in memory. This is
		 * important because we unmap and unpin in 4kb steps later.
		 */
		pfn = kvm_pin_pages(slot, gfn, page_size);
		if (is_error_noslot_pfn(pfn)) {
			gfn += 1;
			continue;
		}

		/* Map into IO address space */
		r = iommu_map(domain, gfn_to_gpa(gfn), pfn_to_hpa(pfn),
			      page_size, flags);
		if (r) {
			printk(KERN_ERR "kvm_iommu_map_address:"
			       "iommu failed to map pfn=%llx\n", pfn);
			kvm_unpin_pages(kvm, pfn, page_size);
			goto unmap_pages;
		}

		gfn += page_size >> PAGE_SHIFT;


	}

	return 0;

unmap_pages:
	kvm_iommu_put_pages(kvm, slot->base_gfn, gfn - slot->base_gfn);
	return r;
}
