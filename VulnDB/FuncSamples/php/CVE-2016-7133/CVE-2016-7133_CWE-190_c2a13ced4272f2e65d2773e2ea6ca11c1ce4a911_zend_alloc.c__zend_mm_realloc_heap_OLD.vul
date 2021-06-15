static void *zend_mm_realloc_heap(zend_mm_heap *heap, void *ptr, size_t size, size_t copy_size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	size_t page_offset;
	size_t old_size;
	size_t new_size;
	void *ret;
#if ZEND_DEBUG
	size_t real_size;
	zend_mm_debug_info *dbg;
#endif

	page_offset = ZEND_MM_ALIGNED_OFFSET(ptr, ZEND_MM_CHUNK_SIZE);
	if (UNEXPECTED(page_offset == 0)) {
		if (UNEXPECTED(ptr == NULL)) {
			return zend_mm_alloc_heap(heap, size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
		old_size = zend_mm_get_huge_block_size(heap, ptr ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
#if ZEND_DEBUG
		real_size = size;
		size = ZEND_MM_ALIGNED_SIZE(size) + ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_debug_info));
#endif
		if (size > ZEND_MM_MAX_LARGE_SIZE) {
#if ZEND_DEBUG
			size = real_size;
#endif
#ifdef ZEND_WIN32
			/* On Windows we don't have ability to extend huge blocks in-place.
			 * We allocate them with 2MB size granularity, to avoid many 
			 * reallocations when they are extended by small pieces
			 */
			new_size = ZEND_MM_ALIGNED_SIZE_EX(size, MAX(REAL_PAGE_SIZE, ZEND_MM_CHUNK_SIZE));
#else
			new_size = ZEND_MM_ALIGNED_SIZE_EX(size, REAL_PAGE_SIZE);
#endif
			if (new_size == old_size) {
#if ZEND_DEBUG
				zend_mm_change_huge_block_size(heap, ptr, new_size, real_size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
#else
				zend_mm_change_huge_block_size(heap, ptr, new_size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
#endif
				return ptr;
			} else if (new_size < old_size) {
				/* unmup tail */
				if (zend_mm_chunk_truncate(heap, ptr, old_size, new_size)) {
#if ZEND_MM_STAT || ZEND_MM_LIMIT
					heap->real_size -= old_size - new_size;
#endif
#if ZEND_MM_STAT
					heap->size -= old_size - new_size;
#endif
#if ZEND_DEBUG
					zend_mm_change_huge_block_size(heap, ptr, new_size, real_size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
#else
					zend_mm_change_huge_block_size(heap, ptr, new_size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
#endif
					return ptr;
				}
			} else /* if (new_size > old_size) */ {
#if ZEND_MM_LIMIT
				if (UNEXPECTED(heap->real_size + (new_size - old_size) > heap->limit)) {
					if (zend_mm_gc(heap) && heap->real_size + (new_size - old_size) <= heap->limit) {
						/* pass */
					} else if (heap->overflow == 0) {
#if ZEND_DEBUG
						zend_mm_safe_error(heap, "Allowed memory size of %zu bytes exhausted at %s:%d (tried to allocate %zu bytes)", heap->limit, __zend_filename, __zend_lineno, size);
#else
						zend_mm_safe_error(heap, "Allowed memory size of %zu bytes exhausted (tried to allocate %zu bytes)", heap->limit, size);
#endif
						return NULL;
					}
				}
#endif
				/* try to map tail right after this block */
				if (zend_mm_chunk_extend(heap, ptr, old_size, new_size)) {
#if ZEND_MM_STAT || ZEND_MM_LIMIT
					heap->real_size += new_size - old_size;
#endif
#if ZEND_MM_STAT
					heap->real_peak = MAX(heap->real_peak, heap->real_size);
					heap->size += new_size - old_size;
					heap->peak = MAX(heap->peak, heap->size);
#endif
#if ZEND_DEBUG
					zend_mm_change_huge_block_size(heap, ptr, new_size, real_size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
#else
					zend_mm_change_huge_block_size(heap, ptr, new_size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
#endif
					return ptr;
				}
			}
		}
	} else {
		zend_mm_chunk *chunk = (zend_mm_chunk*)ZEND_MM_ALIGNED_BASE(ptr, ZEND_MM_CHUNK_SIZE);
		int page_num = (int)(page_offset / ZEND_MM_PAGE_SIZE);
		zend_mm_page_info info = chunk->map[page_num];
#if ZEND_DEBUG
		size_t real_size = size;

		size = ZEND_MM_ALIGNED_SIZE(size) + ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_debug_info));
#endif

		ZEND_MM_CHECK(chunk->heap == heap, "zend_mm_heap corrupted");
		if (info & ZEND_MM_IS_SRUN) {
			int old_bin_num, bin_num;

			old_bin_num = ZEND_MM_SRUN_BIN_NUM(info);
			old_size = bin_data_size[old_bin_num];
			bin_num = ZEND_MM_SMALL_SIZE_TO_BIN(size);
			if (old_bin_num == bin_num) {
#if ZEND_DEBUG
				dbg = zend_mm_get_debug_info(heap, ptr);
				dbg->size = real_size;
				dbg->filename = __zend_filename;
				dbg->orig_filename = __zend_orig_filename;
				dbg->lineno = __zend_lineno;
				dbg->orig_lineno = __zend_orig_lineno;
#endif
				return ptr;
			}
		} else /* if (info & ZEND_MM_IS_LARGE_RUN) */ {
			ZEND_MM_CHECK(ZEND_MM_ALIGNED_OFFSET(page_offset, ZEND_MM_PAGE_SIZE) == 0, "zend_mm_heap corrupted");
			old_size = ZEND_MM_LRUN_PAGES(info) * ZEND_MM_PAGE_SIZE;
			if (size > ZEND_MM_MAX_SMALL_SIZE && size <= ZEND_MM_MAX_LARGE_SIZE) {
				new_size = ZEND_MM_ALIGNED_SIZE_EX(size, ZEND_MM_PAGE_SIZE);
				if (new_size == old_size) {
#if ZEND_DEBUG
					dbg = zend_mm_get_debug_info(heap, ptr);
					dbg->size = real_size;
					dbg->filename = __zend_filename;
					dbg->orig_filename = __zend_orig_filename;
					dbg->lineno = __zend_lineno;
					dbg->orig_lineno = __zend_orig_lineno;
#endif
					return ptr;
				} else if (new_size < old_size) {
					/* free tail pages */
					int new_pages_count = (int)(new_size / ZEND_MM_PAGE_SIZE);
					int rest_pages_count = (int)((old_size - new_size) / ZEND_MM_PAGE_SIZE);

#if ZEND_MM_STAT
					heap->size -= rest_pages_count * ZEND_MM_PAGE_SIZE;
#endif
					chunk->map[page_num] = ZEND_MM_LRUN(new_pages_count);
					chunk->free_pages += rest_pages_count;
					zend_mm_bitset_reset_range(chunk->free_map, page_num + new_pages_count, rest_pages_count);
#if ZEND_DEBUG
					dbg = zend_mm_get_debug_info(heap, ptr);
					dbg->size = real_size;
					dbg->filename = __zend_filename;
					dbg->orig_filename = __zend_orig_filename;
					dbg->lineno = __zend_lineno;
					dbg->orig_lineno = __zend_orig_lineno;
#endif
					return ptr;
				} else /* if (new_size > old_size) */ {
					int new_pages_count = (int)(new_size / ZEND_MM_PAGE_SIZE);
					int old_pages_count = (int)(old_size / ZEND_MM_PAGE_SIZE);

					/* try to allocate tail pages after this block */
					if (page_num + new_pages_count <= ZEND_MM_PAGES &&
					    zend_mm_bitset_is_free_range(chunk->free_map, page_num + old_pages_count, new_pages_count - old_pages_count)) {
#if ZEND_MM_STAT
						do {
							size_t size = heap->size + (new_size - old_size);
							size_t peak = MAX(heap->peak, size);
							heap->size = size;
							heap->peak = peak;
						} while (0);
#endif
						chunk->free_pages -= new_pages_count - old_pages_count;
						zend_mm_bitset_set_range(chunk->free_map, page_num + old_pages_count, new_pages_count - old_pages_count);
						chunk->map[page_num] = ZEND_MM_LRUN(new_pages_count);
#if ZEND_DEBUG
						dbg = zend_mm_get_debug_info(heap, ptr);
						dbg->size = real_size;
						dbg->filename = __zend_filename;
						dbg->orig_filename = __zend_orig_filename;
						dbg->lineno = __zend_lineno;
						dbg->orig_lineno = __zend_orig_lineno;
#endif
						return ptr;
					}
				}
			}
		}
#if ZEND_DEBUG
		size = real_size;
#endif
	}

	/* Naive reallocation */
#if ZEND_MM_STAT
	do {
		size_t orig_peak = heap->peak;
		size_t orig_real_peak = heap->real_peak;
#endif
	ret = zend_mm_alloc_heap(heap, size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
	memcpy(ret, ptr, MIN(old_size, copy_size));
	zend_mm_free_heap(heap, ptr ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
#if ZEND_MM_STAT
		heap->peak = MAX(orig_peak, heap->size);
		heap->real_peak = MAX(orig_real_peak, heap->real_size);
	} while (0);
#endif
	return ret;
}
