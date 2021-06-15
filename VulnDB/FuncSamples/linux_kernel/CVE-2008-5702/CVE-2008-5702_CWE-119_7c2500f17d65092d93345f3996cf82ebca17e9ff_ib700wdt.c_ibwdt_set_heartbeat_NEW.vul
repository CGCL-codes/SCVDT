static int ibwdt_set_heartbeat(int t)
{
	int i;

	if ((t < 0) || (t > 30))
		return -EINVAL;

	for (i = 0x0F; i > -1; i--)
		if (wd_times[i] >= t)
			break;
	wd_margin = i;
	return 0;
}
