static int udf_load_logicalvol(struct super_block *sb, sector_t block,
			       struct kernel_lb_addr *fileset)
{
	struct logicalVolDesc *lvd;
	int i, j, offset;
	uint8_t type;
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct genericPartitionMap *gpm;
	uint16_t ident;
	struct buffer_head *bh;
	int ret = 0;

	bh = udf_read_tagged(sb, block, block, &ident);
	if (!bh)
		return 1;
	BUG_ON(ident != TAG_IDENT_LVD);
	lvd = (struct logicalVolDesc *)bh->b_data;

	ret = udf_sb_alloc_partition_maps(sb, le32_to_cpu(lvd->numPartitionMaps));
	if (ret)
		goto out_bh;

	for (i = 0, offset = 0;
	     i < sbi->s_partitions && offset < le32_to_cpu(lvd->mapTableLength);
	     i++, offset += gpm->partitionMapLength) {
		struct udf_part_map *map = &sbi->s_partmaps[i];
		gpm = (struct genericPartitionMap *)
				&(lvd->partitionMaps[offset]);
		type = gpm->partitionMapType;
		if (type == 1) {
			struct genericPartitionMap1 *gpm1 =
				(struct genericPartitionMap1 *)gpm;
			map->s_partition_type = UDF_TYPE1_MAP15;
			map->s_volumeseqnum = le16_to_cpu(gpm1->volSeqNum);
			map->s_partition_num = le16_to_cpu(gpm1->partitionNum);
			map->s_partition_func = NULL;
		} else if (type == 2) {
			struct udfPartitionMap2 *upm2 =
						(struct udfPartitionMap2 *)gpm;
			if (!strncmp(upm2->partIdent.ident, UDF_ID_VIRTUAL,
						strlen(UDF_ID_VIRTUAL))) {
				u16 suf =
					le16_to_cpu(((__le16 *)upm2->partIdent.
							identSuffix)[0]);
				if (suf < 0x0200) {
					map->s_partition_type =
							UDF_VIRTUAL_MAP15;
					map->s_partition_func =
							udf_get_pblock_virt15;
				} else {
					map->s_partition_type =
							UDF_VIRTUAL_MAP20;
					map->s_partition_func =
							udf_get_pblock_virt20;
				}
			} else if (!strncmp(upm2->partIdent.ident,
						UDF_ID_SPARABLE,
						strlen(UDF_ID_SPARABLE))) {
				uint32_t loc;
				struct sparingTable *st;
				struct sparablePartitionMap *spm =
					(struct sparablePartitionMap *)gpm;

				map->s_partition_type = UDF_SPARABLE_MAP15;
				map->s_type_specific.s_sparing.s_packet_len =
						le16_to_cpu(spm->packetLength);
				for (j = 0; j < spm->numSparingTables; j++) {
					struct buffer_head *bh2;

					loc = le32_to_cpu(
						spm->locSparingTable[j]);
					bh2 = udf_read_tagged(sb, loc, loc,
							     &ident);
					map->s_type_specific.s_sparing.
							s_spar_map[j] = bh2;

					if (bh2 == NULL)
						continue;

					st = (struct sparingTable *)bh2->b_data;
					if (ident != 0 || strncmp(
						st->sparingIdent.ident,
						UDF_ID_SPARING,
						strlen(UDF_ID_SPARING))) {
						brelse(bh2);
						map->s_type_specific.s_sparing.
							s_spar_map[j] = NULL;
					}
				}
				map->s_partition_func = udf_get_pblock_spar15;
			} else if (!strncmp(upm2->partIdent.ident,
						UDF_ID_METADATA,
						strlen(UDF_ID_METADATA))) {
				struct udf_meta_data *mdata =
					&map->s_type_specific.s_metadata;
				struct metadataPartitionMap *mdm =
						(struct metadataPartitionMap *)
						&(lvd->partitionMaps[offset]);
				udf_debug("Parsing Logical vol part %d type %d  id=%s\n",
					  i, type, UDF_ID_METADATA);

				map->s_partition_type = UDF_METADATA_MAP25;
				map->s_partition_func = udf_get_pblock_meta25;

				mdata->s_meta_file_loc   =
					le32_to_cpu(mdm->metadataFileLoc);
				mdata->s_mirror_file_loc =
					le32_to_cpu(mdm->metadataMirrorFileLoc);
				mdata->s_bitmap_file_loc =
					le32_to_cpu(mdm->metadataBitmapFileLoc);
				mdata->s_alloc_unit_size =
					le32_to_cpu(mdm->allocUnitSize);
				mdata->s_align_unit_size =
					le16_to_cpu(mdm->alignUnitSize);
				if (mdm->flags & 0x01)
					mdata->s_flags |= MF_DUPLICATE_MD;

				udf_debug("Metadata Ident suffix=0x%x\n",
					  le16_to_cpu(*(__le16 *)
						      mdm->partIdent.identSuffix));
				udf_debug("Metadata part num=%d\n",
					  le16_to_cpu(mdm->partitionNum));
				udf_debug("Metadata part alloc unit size=%d\n",
					  le32_to_cpu(mdm->allocUnitSize));
				udf_debug("Metadata file loc=%d\n",
					  le32_to_cpu(mdm->metadataFileLoc));
				udf_debug("Mirror file loc=%d\n",
					  le32_to_cpu(mdm->metadataMirrorFileLoc));
				udf_debug("Bitmap file loc=%d\n",
					  le32_to_cpu(mdm->metadataBitmapFileLoc));
				udf_debug("Flags: %d %d\n",
					  mdata->s_flags, mdm->flags);
			} else {
				udf_debug("Unknown ident: %s\n",
					  upm2->partIdent.ident);
				continue;
			}
			map->s_volumeseqnum = le16_to_cpu(upm2->volSeqNum);
			map->s_partition_num = le16_to_cpu(upm2->partitionNum);
		}
		udf_debug("Partition (%d:%d) type %d on volume %d\n",
			  i, map->s_partition_num, type, map->s_volumeseqnum);
	}

	if (fileset) {
		struct long_ad *la = (struct long_ad *)&(lvd->logicalVolContentsUse[0]);

		*fileset = lelb_to_cpu(la->extLocation);
		udf_debug("FileSet found in LogicalVolDesc at block=%d, partition=%d\n",
			  fileset->logicalBlockNum,
			  fileset->partitionReferenceNum);
	}
	if (lvd->integritySeqExt.extLength)
		udf_load_logicalvolint(sb, leea_to_cpu(lvd->integritySeqExt));

out_bh:
	brelse(bh);
	return ret;
}
