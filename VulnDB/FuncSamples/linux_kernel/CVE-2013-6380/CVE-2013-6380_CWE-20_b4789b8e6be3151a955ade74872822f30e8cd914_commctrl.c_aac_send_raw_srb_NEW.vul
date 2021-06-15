static int aac_send_raw_srb(struct aac_dev* dev, void __user * arg)
{
	struct fib* srbfib;
	int status;
	struct aac_srb *srbcmd = NULL;
	struct user_aac_srb *user_srbcmd = NULL;
	struct user_aac_srb __user *user_srb = arg;
	struct aac_srb_reply __user *user_reply;
	struct aac_srb_reply* reply;
	u32 fibsize = 0;
	u32 flags = 0;
	s32 rcode = 0;
	u32 data_dir;
	void __user *sg_user[32];
	void *sg_list[32];
	u32 sg_indx = 0;
	u32 byte_count = 0;
	u32 actual_fibsize64, actual_fibsize = 0;
	int i;


	if (dev->in_reset) {
		dprintk((KERN_DEBUG"aacraid: send raw srb -EBUSY\n"));
		return -EBUSY;
	}
	if (!capable(CAP_SYS_ADMIN)){
		dprintk((KERN_DEBUG"aacraid: No permission to send raw srb\n"));
		return -EPERM;
	}
	/*
	 *	Allocate and initialize a Fib then setup a SRB command
	 */
	if (!(srbfib = aac_fib_alloc(dev))) {
		return -ENOMEM;
	}
	aac_fib_init(srbfib);
	/* raw_srb FIB is not FastResponseCapable */
	srbfib->hw_fib_va->header.XferState &= ~cpu_to_le32(FastResponseCapable);

	srbcmd = (struct aac_srb*) fib_data(srbfib);

	memset(sg_list, 0, sizeof(sg_list)); /* cleanup may take issue */
	if(copy_from_user(&fibsize, &user_srb->count,sizeof(u32))){
		dprintk((KERN_DEBUG"aacraid: Could not copy data size from user\n"));
		rcode = -EFAULT;
		goto cleanup;
	}

	if ((fibsize < (sizeof(struct user_aac_srb) - sizeof(struct user_sgentry))) ||
	    (fibsize > (dev->max_fib_size - sizeof(struct aac_fibhdr)))) {
		rcode = -EINVAL;
		goto cleanup;
	}

	user_srbcmd = kmalloc(fibsize, GFP_KERNEL);
	if (!user_srbcmd) {
		dprintk((KERN_DEBUG"aacraid: Could not make a copy of the srb\n"));
		rcode = -ENOMEM;
		goto cleanup;
	}
	if(copy_from_user(user_srbcmd, user_srb,fibsize)){
		dprintk((KERN_DEBUG"aacraid: Could not copy srb from user\n"));
		rcode = -EFAULT;
		goto cleanup;
	}

	user_reply = arg+fibsize;

	flags = user_srbcmd->flags; /* from user in cpu order */
	// Fix up srb for endian and force some values

	srbcmd->function = cpu_to_le32(SRBF_ExecuteScsi);	// Force this
	srbcmd->channel	 = cpu_to_le32(user_srbcmd->channel);
	srbcmd->id	 = cpu_to_le32(user_srbcmd->id);
	srbcmd->lun	 = cpu_to_le32(user_srbcmd->lun);
	srbcmd->timeout	 = cpu_to_le32(user_srbcmd->timeout);
	srbcmd->flags	 = cpu_to_le32(flags);
	srbcmd->retry_limit = 0; // Obsolete parameter
	srbcmd->cdb_size = cpu_to_le32(user_srbcmd->cdb_size);
	memcpy(srbcmd->cdb, user_srbcmd->cdb, sizeof(srbcmd->cdb));

	switch (flags & (SRB_DataIn | SRB_DataOut)) {
	case SRB_DataOut:
		data_dir = DMA_TO_DEVICE;
		break;
	case (SRB_DataIn | SRB_DataOut):
		data_dir = DMA_BIDIRECTIONAL;
		break;
	case SRB_DataIn:
		data_dir = DMA_FROM_DEVICE;
		break;
	default:
		data_dir = DMA_NONE;
	}
	if (user_srbcmd->sg.count > ARRAY_SIZE(sg_list)) {
		dprintk((KERN_DEBUG"aacraid: too many sg entries %d\n",
		  le32_to_cpu(srbcmd->sg.count)));
		rcode = -EINVAL;
		goto cleanup;
	}
	actual_fibsize = sizeof(struct aac_srb) - sizeof(struct sgentry) +
		((user_srbcmd->sg.count & 0xff) * sizeof(struct sgentry));
	actual_fibsize64 = actual_fibsize + (user_srbcmd->sg.count & 0xff) *
	  (sizeof(struct sgentry64) - sizeof(struct sgentry));
	/* User made a mistake - should not continue */
	if ((actual_fibsize != fibsize) && (actual_fibsize64 != fibsize)) {
		dprintk((KERN_DEBUG"aacraid: Bad Size specified in "
		  "Raw SRB command calculated fibsize=%lu;%lu "
		  "user_srbcmd->sg.count=%d aac_srb=%lu sgentry=%lu;%lu "
		  "issued fibsize=%d\n",
		  actual_fibsize, actual_fibsize64, user_srbcmd->sg.count,
		  sizeof(struct aac_srb), sizeof(struct sgentry),
		  sizeof(struct sgentry64), fibsize));
		rcode = -EINVAL;
		goto cleanup;
	}
	if ((data_dir == DMA_NONE) && user_srbcmd->sg.count) {
		dprintk((KERN_DEBUG"aacraid: SG with no direction specified in Raw SRB command\n"));
		rcode = -EINVAL;
		goto cleanup;
	}
	byte_count = 0;
	if (dev->adapter_info.options & AAC_OPT_SGMAP_HOST64) {
		struct user_sgmap64* upsg = (struct user_sgmap64*)&user_srbcmd->sg;
		struct sgmap64* psg = (struct sgmap64*)&srbcmd->sg;

		/*
		 * This should also catch if user used the 32 bit sgmap
		 */
		if (actual_fibsize64 == fibsize) {
			actual_fibsize = actual_fibsize64;
			for (i = 0; i < upsg->count; i++) {
				u64 addr;
				void* p;
				if (upsg->sg[i].count >
				    ((dev->adapter_info.options &
				     AAC_OPT_NEW_COMM) ?
				      (dev->scsi_host_ptr->max_sectors << 9) :
				      65536)) {
					rcode = -EINVAL;
					goto cleanup;
				}
				/* Does this really need to be GFP_DMA? */
				p = kmalloc(upsg->sg[i].count,GFP_KERNEL|__GFP_DMA);
				if(!p) {
					dprintk((KERN_DEBUG"aacraid: Could not allocate SG buffer - size = %d buffer number %d of %d\n",
					  upsg->sg[i].count,i,upsg->count));
					rcode = -ENOMEM;
					goto cleanup;
				}
				addr = (u64)upsg->sg[i].addr[0];
				addr += ((u64)upsg->sg[i].addr[1]) << 32;
				sg_user[i] = (void __user *)(uintptr_t)addr;
				sg_list[i] = p; // save so we can clean up later
				sg_indx = i;

				if (flags & SRB_DataOut) {
					if(copy_from_user(p,sg_user[i],upsg->sg[i].count)){
						dprintk((KERN_DEBUG"aacraid: Could not copy sg data from user\n"));
						rcode = -EFAULT;
						goto cleanup;
					}
				}
				addr = pci_map_single(dev->pdev, p, upsg->sg[i].count, data_dir);

				psg->sg[i].addr[0] = cpu_to_le32(addr & 0xffffffff);
				psg->sg[i].addr[1] = cpu_to_le32(addr>>32);
				byte_count += upsg->sg[i].count;
				psg->sg[i].count = cpu_to_le32(upsg->sg[i].count);
			}
		} else {
			struct user_sgmap* usg;
			usg = kmalloc(actual_fibsize - sizeof(struct aac_srb)
			  + sizeof(struct sgmap), GFP_KERNEL);
			if (!usg) {
				dprintk((KERN_DEBUG"aacraid: Allocation error in Raw SRB command\n"));
				rcode = -ENOMEM;
				goto cleanup;
			}
			memcpy (usg, upsg, actual_fibsize - sizeof(struct aac_srb)
			  + sizeof(struct sgmap));
			actual_fibsize = actual_fibsize64;

			for (i = 0; i < usg->count; i++) {
				u64 addr;
				void* p;
				if (usg->sg[i].count >
				    ((dev->adapter_info.options &
				     AAC_OPT_NEW_COMM) ?
				      (dev->scsi_host_ptr->max_sectors << 9) :
				      65536)) {
					kfree(usg);
					rcode = -EINVAL;
					goto cleanup;
				}
				/* Does this really need to be GFP_DMA? */
				p = kmalloc(usg->sg[i].count,GFP_KERNEL|__GFP_DMA);
				if(!p) {
					dprintk((KERN_DEBUG "aacraid: Could not allocate SG buffer - size = %d buffer number %d of %d\n",
					  usg->sg[i].count,i,usg->count));
					kfree(usg);
					rcode = -ENOMEM;
					goto cleanup;
				}
				sg_user[i] = (void __user *)(uintptr_t)usg->sg[i].addr;
				sg_list[i] = p; // save so we can clean up later
				sg_indx = i;

				if (flags & SRB_DataOut) {
					if(copy_from_user(p,sg_user[i],upsg->sg[i].count)){
						kfree (usg);
						dprintk((KERN_DEBUG"aacraid: Could not copy sg data from user\n"));
						rcode = -EFAULT;
						goto cleanup;
					}
				}
				addr = pci_map_single(dev->pdev, p, usg->sg[i].count, data_dir);

				psg->sg[i].addr[0] = cpu_to_le32(addr & 0xffffffff);
				psg->sg[i].addr[1] = cpu_to_le32(addr>>32);
				byte_count += usg->sg[i].count;
				psg->sg[i].count = cpu_to_le32(usg->sg[i].count);
			}
			kfree (usg);
		}
		srbcmd->count = cpu_to_le32(byte_count);
		psg->count = cpu_to_le32(sg_indx+1);
		status = aac_fib_send(ScsiPortCommand64, srbfib, actual_fibsize, FsaNormal, 1, 1,NULL,NULL);
	} else {
		struct user_sgmap* upsg = &user_srbcmd->sg;
		struct sgmap* psg = &srbcmd->sg;

		if (actual_fibsize64 == fibsize) {
			struct user_sgmap64* usg = (struct user_sgmap64 *)upsg;
			for (i = 0; i < upsg->count; i++) {
				uintptr_t addr;
				void* p;
				if (usg->sg[i].count >
				    ((dev->adapter_info.options &
				     AAC_OPT_NEW_COMM) ?
				      (dev->scsi_host_ptr->max_sectors << 9) :
				      65536)) {
					rcode = -EINVAL;
					goto cleanup;
				}
				/* Does this really need to be GFP_DMA? */
				p = kmalloc(usg->sg[i].count,GFP_KERNEL|__GFP_DMA);
				if(!p) {
					dprintk((KERN_DEBUG"aacraid: Could not allocate SG buffer - size = %d buffer number %d of %d\n",
					  usg->sg[i].count,i,usg->count));
					rcode = -ENOMEM;
					goto cleanup;
				}
				addr = (u64)usg->sg[i].addr[0];
				addr += ((u64)usg->sg[i].addr[1]) << 32;
				sg_user[i] = (void __user *)addr;
				sg_list[i] = p; // save so we can clean up later
				sg_indx = i;

				if (flags & SRB_DataOut) {
					if(copy_from_user(p,sg_user[i],usg->sg[i].count)){
						dprintk((KERN_DEBUG"aacraid: Could not copy sg data from user\n"));
						rcode = -EFAULT;
						goto cleanup;
					}
				}
				addr = pci_map_single(dev->pdev, p, usg->sg[i].count, data_dir);

				psg->sg[i].addr = cpu_to_le32(addr & 0xffffffff);
				byte_count += usg->sg[i].count;
				psg->sg[i].count = cpu_to_le32(usg->sg[i].count);
			}
		} else {
			for (i = 0; i < upsg->count; i++) {
				dma_addr_t addr;
				void* p;
				if (upsg->sg[i].count >
				    ((dev->adapter_info.options &
				     AAC_OPT_NEW_COMM) ?
				      (dev->scsi_host_ptr->max_sectors << 9) :
				      65536)) {
					rcode = -EINVAL;
					goto cleanup;
				}
				p = kmalloc(upsg->sg[i].count, GFP_KERNEL);
				if (!p) {
					dprintk((KERN_DEBUG"aacraid: Could not allocate SG buffer - size = %d buffer number %d of %d\n",
					  upsg->sg[i].count, i, upsg->count));
					rcode = -ENOMEM;
					goto cleanup;
				}
				sg_user[i] = (void __user *)(uintptr_t)upsg->sg[i].addr;
				sg_list[i] = p; // save so we can clean up later
				sg_indx = i;

				if (flags & SRB_DataOut) {
					if(copy_from_user(p, sg_user[i],
							upsg->sg[i].count)) {
						dprintk((KERN_DEBUG"aacraid: Could not copy sg data from user\n"));
						rcode = -EFAULT;
						goto cleanup;
					}
				}
				addr = pci_map_single(dev->pdev, p,
					upsg->sg[i].count, data_dir);

				psg->sg[i].addr = cpu_to_le32(addr);
				byte_count += upsg->sg[i].count;
				psg->sg[i].count = cpu_to_le32(upsg->sg[i].count);
			}
		}
		srbcmd->count = cpu_to_le32(byte_count);
		psg->count = cpu_to_le32(sg_indx+1);
		status = aac_fib_send(ScsiPortCommand, srbfib, actual_fibsize, FsaNormal, 1, 1, NULL, NULL);
	}
	if (status == -ERESTARTSYS) {
		rcode = -ERESTARTSYS;
		goto cleanup;
	}

	if (status != 0){
		dprintk((KERN_DEBUG"aacraid: Could not send raw srb fib to hba\n"));
		rcode = -ENXIO;
		goto cleanup;
	}

	if (flags & SRB_DataIn) {
		for(i = 0 ; i <= sg_indx; i++){
			byte_count = le32_to_cpu(
			  (dev->adapter_info.options & AAC_OPT_SGMAP_HOST64)
			      ? ((struct sgmap64*)&srbcmd->sg)->sg[i].count
			      : srbcmd->sg.sg[i].count);
			if(copy_to_user(sg_user[i], sg_list[i], byte_count)){
				dprintk((KERN_DEBUG"aacraid: Could not copy sg data to user\n"));
				rcode = -EFAULT;
				goto cleanup;

			}
		}
	}

	reply = (struct aac_srb_reply *) fib_data(srbfib);
	if(copy_to_user(user_reply,reply,sizeof(struct aac_srb_reply))){
		dprintk((KERN_DEBUG"aacraid: Could not copy reply to user\n"));
		rcode = -EFAULT;
		goto cleanup;
	}

cleanup:
	kfree(user_srbcmd);
	for(i=0; i <= sg_indx; i++){
		kfree(sg_list[i]);
	}
	if (rcode != -ERESTARTSYS) {
		aac_fib_complete(srbfib);
		aac_fib_free(srbfib);
	}

	return rcode;
}
