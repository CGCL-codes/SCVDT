void sas_init_disc(struct sas_discovery *disc, struct asd_sas_port *port)
{
	int i;

	static const work_func_t sas_event_fns[DISC_NUM_EVENTS] = {
		[DISCE_DISCOVER_DOMAIN] = sas_discover_domain,
		[DISCE_REVALIDATE_DOMAIN] = sas_revalidate_domain,
		[DISCE_SUSPEND] = sas_suspend_devices,
		[DISCE_RESUME] = sas_resume_devices,
	};

	disc->pending = 0;
	for (i = 0; i < DISC_NUM_EVENTS; i++) {
		INIT_SAS_WORK(&disc->disc_work[i].work, sas_event_fns[i]);
		disc->disc_work[i].port = port;
	}
}
