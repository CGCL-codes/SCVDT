static int hclge_tm_schd_mode_vnet_base_cfg(struct hclge_vport *vport)
{
	struct hnae3_knic_private_info *kinfo = &vport->nic.kinfo;
	struct hclge_dev *hdev = vport->back;
	int ret;
	u8 i;

	if (vport->vport_id >= HNAE3_MAX_TC)
		return -EINVAL;

	ret = hclge_tm_pri_schd_mode_cfg(hdev, vport->vport_id);
	if (ret)
		return ret;

	for (i = 0; i < kinfo->num_tc; i++) {
		u8 sch_mode = hdev->tm_info.tc_info[i].tc_sch_mode;

		ret = hclge_tm_qs_schd_mode_cfg(hdev, vport->qs_offset + i,
						sch_mode);
		if (ret)
			return ret;
	}

	return 0;
}
