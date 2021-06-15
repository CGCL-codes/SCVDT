static int __init snd_mem_init(void)
{
#ifdef CONFIG_PROC_FS
	snd_mem_proc = create_proc_entry(SND_MEM_PROC_FILE, 0644, NULL);
	if (snd_mem_proc)
		snd_mem_proc->proc_fops = &snd_mem_proc_fops;
#endif
	return 0;
}
