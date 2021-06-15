static int serdes_probe(struct platform_device *pdev)
{
	struct phy_provider *provider;
	struct serdes_ctrl *ctrl;
	unsigned int i;
	int ret;

	ctrl = devm_kzalloc(&pdev->dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	ctrl->dev = &pdev->dev;
	ctrl->regs = syscon_node_to_regmap(pdev->dev.parent->of_node);
	if (IS_ERR(ctrl->regs))
		return PTR_ERR(ctrl->regs);

	for (i = 0; i <= SERDES_MAX; i++) {
		ret = serdes_phy_create(ctrl, i, &ctrl->phys[i]);
		if (ret)
			return ret;
	}

	dev_set_drvdata(&pdev->dev, ctrl);

	provider = devm_of_phy_provider_register(ctrl->dev,
						 serdes_simple_xlate);

	return PTR_ERR_OR_ZERO(provider);
}
