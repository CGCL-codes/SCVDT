static int __init pf_init(void)
{				/* preliminary initialisation */
	struct pf_unit *pf;
	int unit;

	if (disable)
		return -EINVAL;

	pf_init_units();

	if (pf_detect())
		return -ENODEV;
	pf_busy = 0;

	if (register_blkdev(major, name)) {
		for (pf = units, unit = 0; unit < PF_UNITS; pf++, unit++) {
			if (!pf->disk)
				continue;
			blk_cleanup_queue(pf->disk->queue);
			blk_mq_free_tag_set(&pf->tag_set);
			put_disk(pf->disk);
		}
		return -EBUSY;
	}

	for (pf = units, unit = 0; unit < PF_UNITS; pf++, unit++) {
		struct gendisk *disk = pf->disk;

		if (!pf->present)
			continue;
		disk->private_data = pf;
		add_disk(disk);
	}
	return 0;
}
