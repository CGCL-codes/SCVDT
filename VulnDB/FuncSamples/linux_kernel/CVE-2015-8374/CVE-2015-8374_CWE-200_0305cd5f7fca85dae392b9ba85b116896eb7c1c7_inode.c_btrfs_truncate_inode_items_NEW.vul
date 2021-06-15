int btrfs_truncate_inode_items(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root,
			       struct inode *inode,
			       u64 new_size, u32 min_type)
{
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_file_extent_item *fi;
	struct btrfs_key key;
	struct btrfs_key found_key;
	u64 extent_start = 0;
	u64 extent_num_bytes = 0;
	u64 extent_offset = 0;
	u64 item_end = 0;
	u64 last_size = new_size;
	u32 found_type = (u8)-1;
	int found_extent;
	int del_item;
	int pending_del_nr = 0;
	int pending_del_slot = 0;
	int extent_type = -1;
	int ret;
	int err = 0;
	u64 ino = btrfs_ino(inode);
	u64 bytes_deleted = 0;
	bool be_nice = 0;
	bool should_throttle = 0;
	bool should_end = 0;

	BUG_ON(new_size > 0 && min_type != BTRFS_EXTENT_DATA_KEY);

	/*
	 * for non-free space inodes and ref cows, we want to back off from
	 * time to time
	 */
	if (!btrfs_is_free_space_inode(inode) &&
	    test_bit(BTRFS_ROOT_REF_COWS, &root->state))
		be_nice = 1;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	path->reada = -1;

	/*
	 * We want to drop from the next block forward in case this new size is
	 * not block aligned since we will be keeping the last block of the
	 * extent just the way it is.
	 */
	if (test_bit(BTRFS_ROOT_REF_COWS, &root->state) ||
	    root == root->fs_info->tree_root)
		btrfs_drop_extent_cache(inode, ALIGN(new_size,
					root->sectorsize), (u64)-1, 0);

	/*
	 * This function is also used to drop the items in the log tree before
	 * we relog the inode, so if root != BTRFS_I(inode)->root, it means
	 * it is used to drop the loged items. So we shouldn't kill the delayed
	 * items.
	 */
	if (min_type == 0 && root == BTRFS_I(inode)->root)
		btrfs_kill_delayed_inode_items(inode);

	key.objectid = ino;
	key.offset = (u64)-1;
	key.type = (u8)-1;

search_again:
	/*
	 * with a 16K leaf size and 128MB extents, you can actually queue
	 * up a huge file in a single leaf.  Most of the time that
	 * bytes_deleted is > 0, it will be huge by the time we get here
	 */
	if (be_nice && bytes_deleted > 32 * 1024 * 1024) {
		if (btrfs_should_end_transaction(trans, root)) {
			err = -EAGAIN;
			goto error;
		}
	}


	path->leave_spinning = 1;
	ret = btrfs_search_slot(trans, root, &key, path, -1, 1);
	if (ret < 0) {
		err = ret;
		goto out;
	}

	if (ret > 0) {
		/* there are no items in the tree for us to truncate, we're
		 * done
		 */
		if (path->slots[0] == 0)
			goto out;
		path->slots[0]--;
	}

	while (1) {
		fi = NULL;
		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
		found_type = found_key.type;

		if (found_key.objectid != ino)
			break;

		if (found_type < min_type)
			break;

		item_end = found_key.offset;
		if (found_type == BTRFS_EXTENT_DATA_KEY) {
			fi = btrfs_item_ptr(leaf, path->slots[0],
					    struct btrfs_file_extent_item);
			extent_type = btrfs_file_extent_type(leaf, fi);
			if (extent_type != BTRFS_FILE_EXTENT_INLINE) {
				item_end +=
				    btrfs_file_extent_num_bytes(leaf, fi);
			} else if (extent_type == BTRFS_FILE_EXTENT_INLINE) {
				item_end += btrfs_file_extent_inline_len(leaf,
							 path->slots[0], fi);
			}
			item_end--;
		}
		if (found_type > min_type) {
			del_item = 1;
		} else {
			if (item_end < new_size)
				break;
			if (found_key.offset >= new_size)
				del_item = 1;
			else
				del_item = 0;
		}
		found_extent = 0;
		/* FIXME, shrink the extent if the ref count is only 1 */
		if (found_type != BTRFS_EXTENT_DATA_KEY)
			goto delete;

		if (del_item)
			last_size = found_key.offset;
		else
			last_size = new_size;

		if (extent_type != BTRFS_FILE_EXTENT_INLINE) {
			u64 num_dec;
			extent_start = btrfs_file_extent_disk_bytenr(leaf, fi);
			if (!del_item) {
				u64 orig_num_bytes =
					btrfs_file_extent_num_bytes(leaf, fi);
				extent_num_bytes = ALIGN(new_size -
						found_key.offset,
						root->sectorsize);
				btrfs_set_file_extent_num_bytes(leaf, fi,
							 extent_num_bytes);
				num_dec = (orig_num_bytes -
					   extent_num_bytes);
				if (test_bit(BTRFS_ROOT_REF_COWS,
					     &root->state) &&
				    extent_start != 0)
					inode_sub_bytes(inode, num_dec);
				btrfs_mark_buffer_dirty(leaf);
			} else {
				extent_num_bytes =
					btrfs_file_extent_disk_num_bytes(leaf,
									 fi);
				extent_offset = found_key.offset -
					btrfs_file_extent_offset(leaf, fi);

				/* FIXME blocksize != 4096 */
				num_dec = btrfs_file_extent_num_bytes(leaf, fi);
				if (extent_start != 0) {
					found_extent = 1;
					if (test_bit(BTRFS_ROOT_REF_COWS,
						     &root->state))
						inode_sub_bytes(inode, num_dec);
				}
			}
		} else if (extent_type == BTRFS_FILE_EXTENT_INLINE) {
			/*
			 * we can't truncate inline items that have had
			 * special encodings
			 */
			if (!del_item &&
			    btrfs_file_extent_encryption(leaf, fi) == 0 &&
			    btrfs_file_extent_other_encoding(leaf, fi) == 0) {

				/*
				 * Need to release path in order to truncate a
				 * compressed extent. So delete any accumulated
				 * extent items so far.
				 */
				if (btrfs_file_extent_compression(leaf, fi) !=
				    BTRFS_COMPRESS_NONE && pending_del_nr) {
					err = btrfs_del_items(trans, root, path,
							      pending_del_slot,
							      pending_del_nr);
					if (err) {
						btrfs_abort_transaction(trans,
									root,
									err);
						goto error;
					}
					pending_del_nr = 0;
				}

				err = truncate_inline_extent(inode, path,
							     &found_key,
							     item_end,
							     new_size);
				if (err) {
					btrfs_abort_transaction(trans,
								root, err);
					goto error;
				}
			} else if (test_bit(BTRFS_ROOT_REF_COWS,
					    &root->state)) {
				inode_sub_bytes(inode, item_end + 1 - new_size);
			}
		}
delete:
		if (del_item) {
			if (!pending_del_nr) {
				/* no pending yet, add ourselves */
				pending_del_slot = path->slots[0];
				pending_del_nr = 1;
			} else if (pending_del_nr &&
				   path->slots[0] + 1 == pending_del_slot) {
				/* hop on the pending chunk */
				pending_del_nr++;
				pending_del_slot = path->slots[0];
			} else {
				BUG();
			}
		} else {
			break;
		}
		should_throttle = 0;

		if (found_extent &&
		    (test_bit(BTRFS_ROOT_REF_COWS, &root->state) ||
		     root == root->fs_info->tree_root)) {
			btrfs_set_path_blocking(path);
			bytes_deleted += extent_num_bytes;
			ret = btrfs_free_extent(trans, root, extent_start,
						extent_num_bytes, 0,
						btrfs_header_owner(leaf),
						ino, extent_offset, 0);
			BUG_ON(ret);
			if (btrfs_should_throttle_delayed_refs(trans, root))
				btrfs_async_run_delayed_refs(root,
					trans->delayed_ref_updates * 2, 0);
			if (be_nice) {
				if (truncate_space_check(trans, root,
							 extent_num_bytes)) {
					should_end = 1;
				}
				if (btrfs_should_throttle_delayed_refs(trans,
								       root)) {
					should_throttle = 1;
				}
			}
		}

		if (found_type == BTRFS_INODE_ITEM_KEY)
			break;

		if (path->slots[0] == 0 ||
		    path->slots[0] != pending_del_slot ||
		    should_throttle || should_end) {
			if (pending_del_nr) {
				ret = btrfs_del_items(trans, root, path,
						pending_del_slot,
						pending_del_nr);
				if (ret) {
					btrfs_abort_transaction(trans,
								root, ret);
					goto error;
				}
				pending_del_nr = 0;
			}
			btrfs_release_path(path);
			if (should_throttle) {
				unsigned long updates = trans->delayed_ref_updates;
				if (updates) {
					trans->delayed_ref_updates = 0;
					ret = btrfs_run_delayed_refs(trans, root, updates * 2);
					if (ret && !err)
						err = ret;
				}
			}
			/*
			 * if we failed to refill our space rsv, bail out
			 * and let the transaction restart
			 */
			if (should_end) {
				err = -EAGAIN;
				goto error;
			}
			goto search_again;
		} else {
			path->slots[0]--;
		}
	}
out:
	if (pending_del_nr) {
		ret = btrfs_del_items(trans, root, path, pending_del_slot,
				      pending_del_nr);
		if (ret)
			btrfs_abort_transaction(trans, root, ret);
	}
error:
	if (root->root_key.objectid != BTRFS_TREE_LOG_OBJECTID)
		btrfs_ordered_update_i_size(inode, last_size, NULL);

	btrfs_free_path(path);

	if (be_nice && bytes_deleted > 32 * 1024 * 1024) {
		unsigned long updates = trans->delayed_ref_updates;
		if (updates) {
			trans->delayed_ref_updates = 0;
			ret = btrfs_run_delayed_refs(trans, root, updates * 2);
			if (ret && !err)
				err = ret;
		}
	}
	return err;
}
