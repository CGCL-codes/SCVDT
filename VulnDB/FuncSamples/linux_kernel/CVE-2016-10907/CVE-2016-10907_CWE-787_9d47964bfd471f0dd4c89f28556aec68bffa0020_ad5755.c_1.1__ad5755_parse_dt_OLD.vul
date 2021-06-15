static struct ad5755_platform_data *ad5755_parse_dt(struct device *dev)
{
	struct device_node *np = dev->of_node;
	struct device_node *pp;
	struct ad5755_platform_data *pdata;
	unsigned int tmp;
	unsigned int tmparray[3];
	int devnr, i;

	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return NULL;

	pdata->ext_dc_dc_compenstation_resistor =
	    of_property_read_bool(np, "adi,ext-dc-dc-compenstation-resistor");

	if (!of_property_read_u32(np, "adi,dc-dc-phase", &tmp))
		pdata->dc_dc_phase = tmp;
	else
		pdata->dc_dc_phase = AD5755_DC_DC_PHASE_ALL_SAME_EDGE;

	pdata->dc_dc_freq = AD5755_DC_DC_FREQ_410kHZ;
	if (!of_property_read_u32(np, "adi,dc-dc-freq-hz", &tmp)) {
		for (i = 0; i < ARRAY_SIZE(ad5755_dcdc_freq_table); i++) {
			if (tmp == ad5755_dcdc_freq_table[i][0]) {
				pdata->dc_dc_freq = ad5755_dcdc_freq_table[i][1];
				break;
			}
		}

		if (i == ARRAY_SIZE(ad5755_dcdc_freq_table)) {
			dev_err(dev,
				"adi,dc-dc-freq out of range selecting 410kHz");
		}
	}

	pdata->dc_dc_maxv = AD5755_DC_DC_MAXV_23V;
	if (!of_property_read_u32(np, "adi,dc-dc-max-microvolt", &tmp)) {
		for (i = 0; i < ARRAY_SIZE(ad5755_dcdc_maxv_table); i++) {
			if (tmp == ad5755_dcdc_maxv_table[i][0]) {
				pdata->dc_dc_maxv = ad5755_dcdc_maxv_table[i][1];
				break;
			}
		}
		if (i == ARRAY_SIZE(ad5755_dcdc_maxv_table)) {
				dev_err(dev,
					"adi,dc-dc-maxv out of range selecting 23V");
		}
	}

	devnr = 0;
	for_each_child_of_node(np, pp) {
		if (devnr > AD5755_NUM_CHANNELS) {
			dev_err(dev,
				"There is to many channels defined in DT\n");
			goto error_out;
		}

		if (!of_property_read_u32(pp, "adi,mode", &tmp))
			pdata->dac[devnr].mode = tmp;
		else
			pdata->dac[devnr].mode = AD5755_MODE_CURRENT_4mA_20mA;

		pdata->dac[devnr].ext_current_sense_resistor =
		    of_property_read_bool(pp, "adi,ext-current-sense-resistor");

		pdata->dac[devnr].enable_voltage_overrange =
		    of_property_read_bool(pp, "adi,enable-voltage-overrange");

		if (!of_property_read_u32_array(pp, "adi,slew", tmparray, 3)) {
			pdata->dac[devnr].slew.enable = tmparray[0];

			pdata->dac[devnr].slew.rate = AD5755_SLEW_RATE_64k;
			for (i = 0; i < ARRAY_SIZE(ad5755_slew_rate_table); i++) {
				if (tmparray[1] == ad5755_slew_rate_table[i][0]) {
					pdata->dac[devnr].slew.rate =
						ad5755_slew_rate_table[i][1];
					break;
				}
			}
			if (i == ARRAY_SIZE(ad5755_slew_rate_table)) {
				dev_err(dev,
					"channel %d slew rate out of range selecting 64kHz",
					devnr);
			}

			pdata->dac[devnr].slew.step_size = AD5755_SLEW_STEP_SIZE_1;
			for (i = 0; i < ARRAY_SIZE(ad5755_slew_step_table); i++) {
				if (tmparray[2] == ad5755_slew_step_table[i][0]) {
					pdata->dac[devnr].slew.step_size =
						ad5755_slew_step_table[i][1];
					break;
				}
			}
			if (i == ARRAY_SIZE(ad5755_slew_step_table)) {
				dev_err(dev,
					"channel %d slew step size out of range selecting 1 LSB",
					devnr);
			}
		} else {
			pdata->dac[devnr].slew.enable = false;
			pdata->dac[devnr].slew.rate = AD5755_SLEW_RATE_64k;
			pdata->dac[devnr].slew.step_size =
			    AD5755_SLEW_STEP_SIZE_1;
		}
		devnr++;
	}

	return pdata;

 error_out:
	devm_kfree(dev, pdata);
	return NULL;
}
