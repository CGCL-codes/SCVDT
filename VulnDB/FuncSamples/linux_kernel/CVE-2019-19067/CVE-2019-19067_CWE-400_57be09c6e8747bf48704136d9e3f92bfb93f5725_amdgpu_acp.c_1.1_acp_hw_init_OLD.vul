static int acp_hw_init(void *handle)
{
	int r, i;
	uint64_t acp_base;
	u32 val = 0;
	u32 count = 0;
	struct device *dev;
	struct i2s_platform_data *i2s_pdata;

	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	const struct amdgpu_ip_block *ip_block =
		amdgpu_device_ip_get_ip_block(adev, AMD_IP_BLOCK_TYPE_ACP);

	if (!ip_block)
		return -EINVAL;

	r = amd_acp_hw_init(adev->acp.cgs_device,
			    ip_block->version->major, ip_block->version->minor);
	/* -ENODEV means board uses AZ rather than ACP */
	if (r == -ENODEV) {
		amdgpu_dpm_set_powergating_by_smu(adev, AMD_IP_BLOCK_TYPE_ACP, true);
		return 0;
	} else if (r) {
		return r;
	}

	if (adev->rmmio_size == 0 || adev->rmmio_size < 0x5289)
		return -EINVAL;

	acp_base = adev->rmmio_base;


	adev->acp.acp_genpd = kzalloc(sizeof(struct acp_pm_domain), GFP_KERNEL);
	if (adev->acp.acp_genpd == NULL)
		return -ENOMEM;

	adev->acp.acp_genpd->gpd.name = "ACP_AUDIO";
	adev->acp.acp_genpd->gpd.power_off = acp_poweroff;
	adev->acp.acp_genpd->gpd.power_on = acp_poweron;


	adev->acp.acp_genpd->adev = adev;

	pm_genpd_init(&adev->acp.acp_genpd->gpd, NULL, false);

	adev->acp.acp_cell = kcalloc(ACP_DEVS, sizeof(struct mfd_cell),
							GFP_KERNEL);

	if (adev->acp.acp_cell == NULL)
		return -ENOMEM;

	adev->acp.acp_res = kcalloc(5, sizeof(struct resource), GFP_KERNEL);
	if (adev->acp.acp_res == NULL) {
		kfree(adev->acp.acp_cell);
		return -ENOMEM;
	}

	i2s_pdata = kcalloc(3, sizeof(struct i2s_platform_data), GFP_KERNEL);
	if (i2s_pdata == NULL) {
		kfree(adev->acp.acp_res);
		kfree(adev->acp.acp_cell);
		return -ENOMEM;
	}

	switch (adev->asic_type) {
	case CHIP_STONEY:
		i2s_pdata[0].quirks = DW_I2S_QUIRK_COMP_REG_OFFSET |
			DW_I2S_QUIRK_16BIT_IDX_OVERRIDE;
		break;
	default:
		i2s_pdata[0].quirks = DW_I2S_QUIRK_COMP_REG_OFFSET;
	}
	i2s_pdata[0].cap = DWC_I2S_PLAY;
	i2s_pdata[0].snd_rates = SNDRV_PCM_RATE_8000_96000;
	i2s_pdata[0].i2s_reg_comp1 = ACP_I2S_COMP1_PLAY_REG_OFFSET;
	i2s_pdata[0].i2s_reg_comp2 = ACP_I2S_COMP2_PLAY_REG_OFFSET;
	switch (adev->asic_type) {
	case CHIP_STONEY:
		i2s_pdata[1].quirks = DW_I2S_QUIRK_COMP_REG_OFFSET |
			DW_I2S_QUIRK_COMP_PARAM1 |
			DW_I2S_QUIRK_16BIT_IDX_OVERRIDE;
		break;
	default:
		i2s_pdata[1].quirks = DW_I2S_QUIRK_COMP_REG_OFFSET |
			DW_I2S_QUIRK_COMP_PARAM1;
	}

	i2s_pdata[1].cap = DWC_I2S_RECORD;
	i2s_pdata[1].snd_rates = SNDRV_PCM_RATE_8000_96000;
	i2s_pdata[1].i2s_reg_comp1 = ACP_I2S_COMP1_CAP_REG_OFFSET;
	i2s_pdata[1].i2s_reg_comp2 = ACP_I2S_COMP2_CAP_REG_OFFSET;

	i2s_pdata[2].quirks = DW_I2S_QUIRK_COMP_REG_OFFSET;
	switch (adev->asic_type) {
	case CHIP_STONEY:
		i2s_pdata[2].quirks |= DW_I2S_QUIRK_16BIT_IDX_OVERRIDE;
		break;
	default:
		break;
	}

	i2s_pdata[2].cap = DWC_I2S_PLAY | DWC_I2S_RECORD;
	i2s_pdata[2].snd_rates = SNDRV_PCM_RATE_8000_96000;
	i2s_pdata[2].i2s_reg_comp1 = ACP_BT_COMP1_REG_OFFSET;
	i2s_pdata[2].i2s_reg_comp2 = ACP_BT_COMP2_REG_OFFSET;

	adev->acp.acp_res[0].name = "acp2x_dma";
	adev->acp.acp_res[0].flags = IORESOURCE_MEM;
	adev->acp.acp_res[0].start = acp_base;
	adev->acp.acp_res[0].end = acp_base + ACP_DMA_REGS_END;

	adev->acp.acp_res[1].name = "acp2x_dw_i2s_play";
	adev->acp.acp_res[1].flags = IORESOURCE_MEM;
	adev->acp.acp_res[1].start = acp_base + ACP_I2S_PLAY_REGS_START;
	adev->acp.acp_res[1].end = acp_base + ACP_I2S_PLAY_REGS_END;

	adev->acp.acp_res[2].name = "acp2x_dw_i2s_cap";
	adev->acp.acp_res[2].flags = IORESOURCE_MEM;
	adev->acp.acp_res[2].start = acp_base + ACP_I2S_CAP_REGS_START;
	adev->acp.acp_res[2].end = acp_base + ACP_I2S_CAP_REGS_END;

	adev->acp.acp_res[3].name = "acp2x_dw_bt_i2s_play_cap";
	adev->acp.acp_res[3].flags = IORESOURCE_MEM;
	adev->acp.acp_res[3].start = acp_base + ACP_BT_PLAY_REGS_START;
	adev->acp.acp_res[3].end = acp_base + ACP_BT_PLAY_REGS_END;

	adev->acp.acp_res[4].name = "acp2x_dma_irq";
	adev->acp.acp_res[4].flags = IORESOURCE_IRQ;
	adev->acp.acp_res[4].start = amdgpu_irq_create_mapping(adev, 162);
	adev->acp.acp_res[4].end = adev->acp.acp_res[4].start;

	adev->acp.acp_cell[0].name = "acp_audio_dma";
	adev->acp.acp_cell[0].num_resources = 5;
	adev->acp.acp_cell[0].resources = &adev->acp.acp_res[0];
	adev->acp.acp_cell[0].platform_data = &adev->asic_type;
	adev->acp.acp_cell[0].pdata_size = sizeof(adev->asic_type);

	adev->acp.acp_cell[1].name = "designware-i2s";
	adev->acp.acp_cell[1].num_resources = 1;
	adev->acp.acp_cell[1].resources = &adev->acp.acp_res[1];
	adev->acp.acp_cell[1].platform_data = &i2s_pdata[0];
	adev->acp.acp_cell[1].pdata_size = sizeof(struct i2s_platform_data);

	adev->acp.acp_cell[2].name = "designware-i2s";
	adev->acp.acp_cell[2].num_resources = 1;
	adev->acp.acp_cell[2].resources = &adev->acp.acp_res[2];
	adev->acp.acp_cell[2].platform_data = &i2s_pdata[1];
	adev->acp.acp_cell[2].pdata_size = sizeof(struct i2s_platform_data);

	adev->acp.acp_cell[3].name = "designware-i2s";
	adev->acp.acp_cell[3].num_resources = 1;
	adev->acp.acp_cell[3].resources = &adev->acp.acp_res[3];
	adev->acp.acp_cell[3].platform_data = &i2s_pdata[2];
	adev->acp.acp_cell[3].pdata_size = sizeof(struct i2s_platform_data);

	r = mfd_add_hotplug_devices(adev->acp.parent, adev->acp.acp_cell,
								ACP_DEVS);
	if (r)
		return r;

	for (i = 0; i < ACP_DEVS ; i++) {
		dev = get_mfd_cell_dev(adev->acp.acp_cell[i].name, i);
		r = pm_genpd_add_device(&adev->acp.acp_genpd->gpd, dev);
		if (r) {
			dev_err(dev, "Failed to add dev to genpd\n");
			return r;
		}
	}


	/* Assert Soft reset of ACP */
	val = cgs_read_register(adev->acp.cgs_device, mmACP_SOFT_RESET);

	val |= ACP_SOFT_RESET__SoftResetAud_MASK;
	cgs_write_register(adev->acp.cgs_device, mmACP_SOFT_RESET, val);

	count = ACP_SOFT_RESET_DONE_TIME_OUT_VALUE;
	while (true) {
		val = cgs_read_register(adev->acp.cgs_device, mmACP_SOFT_RESET);
		if (ACP_SOFT_RESET__SoftResetAudDone_MASK ==
		    (val & ACP_SOFT_RESET__SoftResetAudDone_MASK))
			break;
		if (--count == 0) {
			dev_err(&adev->pdev->dev, "Failed to reset ACP\n");
			return -ETIMEDOUT;
		}
		udelay(100);
	}
	/* Enable clock to ACP and wait until the clock is enabled */
	val = cgs_read_register(adev->acp.cgs_device, mmACP_CONTROL);
	val = val | ACP_CONTROL__ClkEn_MASK;
	cgs_write_register(adev->acp.cgs_device, mmACP_CONTROL, val);

	count = ACP_CLOCK_EN_TIME_OUT_VALUE;

	while (true) {
		val = cgs_read_register(adev->acp.cgs_device, mmACP_STATUS);
		if (val & (u32) 0x1)
			break;
		if (--count == 0) {
			dev_err(&adev->pdev->dev, "Failed to reset ACP\n");
			return -ETIMEDOUT;
		}
		udelay(100);
	}
	/* Deassert the SOFT RESET flags */
	val = cgs_read_register(adev->acp.cgs_device, mmACP_SOFT_RESET);
	val &= ~ACP_SOFT_RESET__SoftResetAud_MASK;
	cgs_write_register(adev->acp.cgs_device, mmACP_SOFT_RESET, val);
	return 0;
}
