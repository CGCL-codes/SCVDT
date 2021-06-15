static void smp_task_done(struct sas_task *task)
{
	del_timer(&task->slow_task->timer);
	complete(&task->slow_task->completion);
}
