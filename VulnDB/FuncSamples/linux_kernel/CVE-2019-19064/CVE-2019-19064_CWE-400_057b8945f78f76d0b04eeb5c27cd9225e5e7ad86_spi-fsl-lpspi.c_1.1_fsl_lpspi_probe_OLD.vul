static int fsl_lpspi_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct fsl_lpspi_data *fsl_lpspi;
	struct spi_controller *controller;
	struct spi_imx_master *lpspi_platform_info =
		dev_get_platdata(&pdev->dev);
	struct resource *res;
	int i, ret, irq;
	u32 temp;
	bool is_slave;

	is_slave = of_property_read_bool((&pdev->dev)->of_node, "spi-slave");
	if (is_slave)
		controller = spi_alloc_slave(&pdev->dev,
					sizeof(struct fsl_lpspi_data));
	else
		controller = spi_alloc_master(&pdev->dev,
					sizeof(struct fsl_lpspi_data));

	if (!controller)
		return -ENOMEM;

	platform_set_drvdata(pdev, controller);

	fsl_lpspi = spi_controller_get_devdata(controller);
	fsl_lpspi->dev = &pdev->dev;
	fsl_lpspi->is_slave = is_slave;

	if (!fsl_lpspi->is_slave) {
		for (i = 0; i < controller->num_chipselect; i++) {
			int cs_gpio = of_get_named_gpio(np, "cs-gpios", i);

			if (!gpio_is_valid(cs_gpio) && lpspi_platform_info)
				cs_gpio = lpspi_platform_info->chipselect[i];

			fsl_lpspi->chipselect[i] = cs_gpio;
			if (!gpio_is_valid(cs_gpio))
				continue;

			ret = devm_gpio_request(&pdev->dev,
						fsl_lpspi->chipselect[i],
						DRIVER_NAME);
			if (ret) {
				dev_err(&pdev->dev, "can't get cs gpios\n");
				goto out_controller_put;
			}
		}
		controller->cs_gpios = fsl_lpspi->chipselect;
		controller->prepare_message = fsl_lpspi_prepare_message;
	}

	controller->bits_per_word_mask = SPI_BPW_RANGE_MASK(8, 32);
	controller->transfer_one = fsl_lpspi_transfer_one;
	controller->prepare_transfer_hardware = lpspi_prepare_xfer_hardware;
	controller->unprepare_transfer_hardware = lpspi_unprepare_xfer_hardware;
	controller->mode_bits = SPI_CPOL | SPI_CPHA | SPI_CS_HIGH;
	controller->flags = SPI_MASTER_MUST_RX | SPI_MASTER_MUST_TX;
	controller->dev.of_node = pdev->dev.of_node;
	controller->bus_num = pdev->id;
	controller->slave_abort = fsl_lpspi_slave_abort;

	init_completion(&fsl_lpspi->xfer_done);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	fsl_lpspi->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(fsl_lpspi->base)) {
		ret = PTR_ERR(fsl_lpspi->base);
		goto out_controller_put;
	}
	fsl_lpspi->base_phys = res->start;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		ret = irq;
		goto out_controller_put;
	}

	ret = devm_request_irq(&pdev->dev, irq, fsl_lpspi_isr, 0,
			       dev_name(&pdev->dev), fsl_lpspi);
	if (ret) {
		dev_err(&pdev->dev, "can't get irq%d: %d\n", irq, ret);
		goto out_controller_put;
	}

	fsl_lpspi->clk_per = devm_clk_get(&pdev->dev, "per");
	if (IS_ERR(fsl_lpspi->clk_per)) {
		ret = PTR_ERR(fsl_lpspi->clk_per);
		goto out_controller_put;
	}

	fsl_lpspi->clk_ipg = devm_clk_get(&pdev->dev, "ipg");
	if (IS_ERR(fsl_lpspi->clk_ipg)) {
		ret = PTR_ERR(fsl_lpspi->clk_ipg);
		goto out_controller_put;
	}

	/* enable the clock */
	ret = fsl_lpspi_init_rpm(fsl_lpspi);
	if (ret)
		goto out_controller_put;

	ret = pm_runtime_get_sync(fsl_lpspi->dev);
	if (ret < 0) {
		dev_err(fsl_lpspi->dev, "failed to enable clock\n");
		return ret;
	}

	temp = readl(fsl_lpspi->base + IMX7ULP_PARAM);
	fsl_lpspi->txfifosize = 1 << (temp & 0x0f);
	fsl_lpspi->rxfifosize = 1 << ((temp >> 8) & 0x0f);

	ret = fsl_lpspi_dma_init(&pdev->dev, fsl_lpspi, controller);
	if (ret == -EPROBE_DEFER)
		goto out_controller_put;

	if (ret < 0)
		dev_err(&pdev->dev, "dma setup error %d, use pio\n", ret);

	ret = devm_spi_register_controller(&pdev->dev, controller);
	if (ret < 0) {
		dev_err(&pdev->dev, "spi_register_controller error.\n");
		goto out_controller_put;
	}

	return 0;

out_controller_put:
	spi_controller_put(controller);

	return ret;
}
