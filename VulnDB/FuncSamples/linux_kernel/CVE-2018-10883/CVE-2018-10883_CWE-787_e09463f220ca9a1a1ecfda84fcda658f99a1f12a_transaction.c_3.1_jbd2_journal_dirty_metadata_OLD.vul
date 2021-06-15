int jbd2_journal_dirty_metadata(handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	struct journal_head *jh;
	int ret = 0;

	if (is_handle_aborted(handle))
		return -EROFS;
	if (!buffer_jbd(bh)) {
		ret = -EUCLEAN;
		goto out;
	}
	/*
	 * We don't grab jh reference here since the buffer must be part
	 * of the running transaction.
	 */
	jh = bh2jh(bh);
	/*
	 * This and the following assertions are unreliable since we may see jh
	 * in inconsistent state unless we grab bh_state lock. But this is
	 * crucial to catch bugs so let's do a reliable check until the
	 * lockless handling is fully proven.
	 */
	if (jh->b_transaction != transaction &&
	    jh->b_next_transaction != transaction) {
		jbd_lock_bh_state(bh);
		J_ASSERT_JH(jh, jh->b_transaction == transaction ||
				jh->b_next_transaction == transaction);
		jbd_unlock_bh_state(bh);
	}
	if (jh->b_modified == 1) {
		/* If it's in our transaction it must be in BJ_Metadata list. */
		if (jh->b_transaction == transaction &&
		    jh->b_jlist != BJ_Metadata) {
			jbd_lock_bh_state(bh);
			J_ASSERT_JH(jh, jh->b_transaction != transaction ||
					jh->b_jlist == BJ_Metadata);
			jbd_unlock_bh_state(bh);
		}
		goto out;
	}

	journal = transaction->t_journal;
	jbd_debug(5, "journal_head %p\n", jh);
	JBUFFER_TRACE(jh, "entry");

	jbd_lock_bh_state(bh);

	if (jh->b_modified == 0) {
		/*
		 * This buffer's got modified and becoming part
		 * of the transaction. This needs to be done
		 * once a transaction -bzzz
		 */
		jh->b_modified = 1;
		if (handle->h_buffer_credits <= 0) {
			ret = -ENOSPC;
			goto out_unlock_bh;
		}
		handle->h_buffer_credits--;
	}

	/*
	 * fastpath, to avoid expensive locking.  If this buffer is already
	 * on the running transaction's metadata list there is nothing to do.
	 * Nobody can take it off again because there is a handle open.
	 * I _think_ we're OK here with SMP barriers - a mistaken decision will
	 * result in this test being false, so we go in and take the locks.
	 */
	if (jh->b_transaction == transaction && jh->b_jlist == BJ_Metadata) {
		JBUFFER_TRACE(jh, "fastpath");
		if (unlikely(jh->b_transaction !=
			     journal->j_running_transaction)) {
			printk(KERN_ERR "JBD2: %s: "
			       "jh->b_transaction (%llu, %p, %u) != "
			       "journal->j_running_transaction (%p, %u)\n",
			       journal->j_devname,
			       (unsigned long long) bh->b_blocknr,
			       jh->b_transaction,
			       jh->b_transaction ? jh->b_transaction->t_tid : 0,
			       journal->j_running_transaction,
			       journal->j_running_transaction ?
			       journal->j_running_transaction->t_tid : 0);
			ret = -EINVAL;
		}
		goto out_unlock_bh;
	}

	set_buffer_jbddirty(bh);

	/*
	 * Metadata already on the current transaction list doesn't
	 * need to be filed.  Metadata on another transaction's list must
	 * be committing, and will be refiled once the commit completes:
	 * leave it alone for now.
	 */
	if (jh->b_transaction != transaction) {
		JBUFFER_TRACE(jh, "already on other transaction");
		if (unlikely(((jh->b_transaction !=
			       journal->j_committing_transaction)) ||
			     (jh->b_next_transaction != transaction))) {
			printk(KERN_ERR "jbd2_journal_dirty_metadata: %s: "
			       "bad jh for block %llu: "
			       "transaction (%p, %u), "
			       "jh->b_transaction (%p, %u), "
			       "jh->b_next_transaction (%p, %u), jlist %u\n",
			       journal->j_devname,
			       (unsigned long long) bh->b_blocknr,
			       transaction, transaction->t_tid,
			       jh->b_transaction,
			       jh->b_transaction ?
			       jh->b_transaction->t_tid : 0,
			       jh->b_next_transaction,
			       jh->b_next_transaction ?
			       jh->b_next_transaction->t_tid : 0,
			       jh->b_jlist);
			WARN_ON(1);
			ret = -EINVAL;
		}
		/* And this case is illegal: we can't reuse another
		 * transaction's data buffer, ever. */
		goto out_unlock_bh;
	}

	/* That test should have eliminated the following case: */
	J_ASSERT_JH(jh, jh->b_frozen_data == NULL);

	JBUFFER_TRACE(jh, "file as BJ_Metadata");
	spin_lock(&journal->j_list_lock);
	__jbd2_journal_file_buffer(jh, transaction, BJ_Metadata);
	spin_unlock(&journal->j_list_lock);
out_unlock_bh:
	jbd_unlock_bh_state(bh);
out:
	JBUFFER_TRACE(jh, "exit");
	return ret;
}
