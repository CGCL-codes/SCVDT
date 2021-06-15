int ring_buffer_resize(struct ring_buffer *buffer, unsigned long size,
			int cpu_id)
{
	struct ring_buffer_per_cpu *cpu_buffer;
	unsigned long nr_pages;
	int cpu, err = 0;

	/*
	 * Always succeed at resizing a non-existent buffer:
	 */
	if (!buffer)
		return size;

	/* Make sure the requested buffer exists */
	if (cpu_id != RING_BUFFER_ALL_CPUS &&
	    !cpumask_test_cpu(cpu_id, buffer->cpumask))
		return size;

	nr_pages = DIV_ROUND_UP(size, BUF_PAGE_SIZE);

	/* we need a minimum of two pages */
	if (nr_pages < 2)
		nr_pages = 2;

	size = nr_pages * BUF_PAGE_SIZE;

	/*
	 * Don't succeed if resizing is disabled, as a reader might be
	 * manipulating the ring buffer and is expecting a sane state while
	 * this is true.
	 */
	if (atomic_read(&buffer->resize_disabled))
		return -EBUSY;

	/* prevent another thread from changing buffer sizes */
	mutex_lock(&buffer->mutex);

	if (cpu_id == RING_BUFFER_ALL_CPUS) {
		/* calculate the pages to update */
		for_each_buffer_cpu(buffer, cpu) {
			cpu_buffer = buffer->buffers[cpu];

			cpu_buffer->nr_pages_to_update = nr_pages -
							cpu_buffer->nr_pages;
			/*
			 * nothing more to do for removing pages or no update
			 */
			if (cpu_buffer->nr_pages_to_update <= 0)
				continue;
			/*
			 * to add pages, make sure all new pages can be
			 * allocated without receiving ENOMEM
			 */
			INIT_LIST_HEAD(&cpu_buffer->new_pages);
			if (__rb_allocate_pages(cpu_buffer->nr_pages_to_update,
						&cpu_buffer->new_pages, cpu)) {
				/* not enough memory for new pages */
				err = -ENOMEM;
				goto out_err;
			}
		}

		get_online_cpus();
		/*
		 * Fire off all the required work handlers
		 * We can't schedule on offline CPUs, but it's not necessary
		 * since we can change their buffer sizes without any race.
		 */
		for_each_buffer_cpu(buffer, cpu) {
			cpu_buffer = buffer->buffers[cpu];
			if (!cpu_buffer->nr_pages_to_update)
				continue;

			/* Can't run something on an offline CPU. */
			if (!cpu_online(cpu)) {
				rb_update_pages(cpu_buffer);
				cpu_buffer->nr_pages_to_update = 0;
			} else {
				schedule_work_on(cpu,
						&cpu_buffer->update_pages_work);
			}
		}

		/* wait for all the updates to complete */
		for_each_buffer_cpu(buffer, cpu) {
			cpu_buffer = buffer->buffers[cpu];
			if (!cpu_buffer->nr_pages_to_update)
				continue;

			if (cpu_online(cpu))
				wait_for_completion(&cpu_buffer->update_done);
			cpu_buffer->nr_pages_to_update = 0;
		}

		put_online_cpus();
	} else {
		/* Make sure this CPU has been intitialized */
		if (!cpumask_test_cpu(cpu_id, buffer->cpumask))
			goto out;

		cpu_buffer = buffer->buffers[cpu_id];

		if (nr_pages == cpu_buffer->nr_pages)
			goto out;

		cpu_buffer->nr_pages_to_update = nr_pages -
						cpu_buffer->nr_pages;

		INIT_LIST_HEAD(&cpu_buffer->new_pages);
		if (cpu_buffer->nr_pages_to_update > 0 &&
			__rb_allocate_pages(cpu_buffer->nr_pages_to_update,
					    &cpu_buffer->new_pages, cpu_id)) {
			err = -ENOMEM;
			goto out_err;
		}

		get_online_cpus();

		/* Can't run something on an offline CPU. */
		if (!cpu_online(cpu_id))
			rb_update_pages(cpu_buffer);
		else {
			schedule_work_on(cpu_id,
					 &cpu_buffer->update_pages_work);
			wait_for_completion(&cpu_buffer->update_done);
		}

		cpu_buffer->nr_pages_to_update = 0;
		put_online_cpus();
	}

 out:
	/*
	 * The ring buffer resize can happen with the ring buffer
	 * enabled, so that the update disturbs the tracing as little
	 * as possible. But if the buffer is disabled, we do not need
	 * to worry about that, and we can take the time to verify
	 * that the buffer is not corrupt.
	 */
	if (atomic_read(&buffer->record_disabled)) {
		atomic_inc(&buffer->record_disabled);
		/*
		 * Even though the buffer was disabled, we must make sure
		 * that it is truly disabled before calling rb_check_pages.
		 * There could have been a race between checking
		 * record_disable and incrementing it.
		 */
		synchronize_sched();
		for_each_buffer_cpu(buffer, cpu) {
			cpu_buffer = buffer->buffers[cpu];
			rb_check_pages(cpu_buffer);
		}
		atomic_dec(&buffer->record_disabled);
	}

	mutex_unlock(&buffer->mutex);
	return size;

 out_err:
	for_each_buffer_cpu(buffer, cpu) {
		struct buffer_page *bpage, *tmp;

		cpu_buffer = buffer->buffers[cpu];
		cpu_buffer->nr_pages_to_update = 0;

		if (list_empty(&cpu_buffer->new_pages))
			continue;

		list_for_each_entry_safe(bpage, tmp, &cpu_buffer->new_pages,
					list) {
			list_del_init(&bpage->list);
			free_buffer_page(bpage);
		}
	}
	mutex_unlock(&buffer->mutex);
	return err;
}
