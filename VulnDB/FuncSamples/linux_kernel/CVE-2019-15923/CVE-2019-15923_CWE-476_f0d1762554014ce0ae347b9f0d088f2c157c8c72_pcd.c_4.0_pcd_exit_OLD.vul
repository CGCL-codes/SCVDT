static void __exit pcd_exit(void)
{
	struct pcd_unit *cd;
	int unit;

	for (unit = 0, cd = pcd; unit < PCD_UNITS; unit++, cd++) {
		if (cd->present) {
			del_gendisk(cd->disk);
			pi_release(cd->pi);
			unregister_cdrom(&cd->info);
		}
		blk_cleanup_queue(cd->disk->queue);
		blk_mq_free_tag_set(&cd->tag_set);
		put_disk(cd->disk);
	}
	unregister_blkdev(major, name);
	pi_unregister_driver(par_drv);
}
