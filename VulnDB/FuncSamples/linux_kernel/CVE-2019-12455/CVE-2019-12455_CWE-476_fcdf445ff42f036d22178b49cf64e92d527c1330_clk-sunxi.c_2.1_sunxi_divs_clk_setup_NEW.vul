static struct clk ** __init sunxi_divs_clk_setup(struct device_node *node,
						 const struct divs_data *data)
{
	struct clk_onecell_data *clk_data;
	const char *parent;
	const char *clk_name;
	struct clk **clks, *pclk;
	struct clk_hw *gate_hw, *rate_hw;
	const struct clk_ops *rate_ops;
	struct clk_gate *gate = NULL;
	struct clk_fixed_factor *fix_factor;
	struct clk_divider *divider;
	struct factors_data factors = *data->factors;
	char *derived_name = NULL;
	void __iomem *reg;
	int ndivs = SUNXI_DIVS_MAX_QTY, i = 0;
	int flags, clkflags;

	/* if number of children known, use it */
	if (data->ndivs)
		ndivs = data->ndivs;

	/* Try to find a name for base factor clock */
	for (i = 0; i < ndivs; i++) {
		if (data->div[i].self) {
			of_property_read_string_index(node, "clock-output-names",
						      i, &factors.name);
			break;
		}
	}
	/* If we don't have a .self clk use the first output-name up to '_' */
	if (factors.name == NULL) {
		char *endp;

		of_property_read_string_index(node, "clock-output-names",
						      0, &clk_name);
		endp = strchr(clk_name, '_');
		if (endp) {
			derived_name = kstrndup(clk_name, endp - clk_name,
						GFP_KERNEL);
			if (!derived_name)
				return NULL;
			factors.name = derived_name;
		} else {
			factors.name = clk_name;
		}
	}

	/* Set up factor clock that we will be dividing */
	pclk = sunxi_factors_clk_setup(node, &factors);
	if (!pclk)
		return NULL;

	parent = __clk_get_name(pclk);
	kfree(derived_name);

	reg = of_iomap(node, 0);
	if (!reg) {
		pr_err("Could not map registers for divs-clk: %pOF\n", node);
		return NULL;
	}

	clk_data = kmalloc(sizeof(struct clk_onecell_data), GFP_KERNEL);
	if (!clk_data)
		goto out_unmap;

	clks = kcalloc(ndivs, sizeof(*clks), GFP_KERNEL);
	if (!clks)
		goto free_clkdata;

	clk_data->clks = clks;

	/* It's not a good idea to have automatic reparenting changing
	 * our RAM clock! */
	clkflags = !strcmp("pll5", parent) ? 0 : CLK_SET_RATE_PARENT;

	for (i = 0; i < ndivs; i++) {
		if (of_property_read_string_index(node, "clock-output-names",
						  i, &clk_name) != 0)
			break;

		/* If this is the base factor clock, only update clks */
		if (data->div[i].self) {
			clk_data->clks[i] = pclk;
			continue;
		}

		gate_hw = NULL;
		rate_hw = NULL;
		rate_ops = NULL;

		/* If this leaf clock can be gated, create a gate */
		if (data->div[i].gate) {
			gate = kzalloc(sizeof(*gate), GFP_KERNEL);
			if (!gate)
				goto free_clks;

			gate->reg = reg;
			gate->bit_idx = data->div[i].gate;
			gate->lock = &clk_lock;

			gate_hw = &gate->hw;
		}

		/* Leaves can be fixed or configurable divisors */
		if (data->div[i].fixed) {
			fix_factor = kzalloc(sizeof(*fix_factor), GFP_KERNEL);
			if (!fix_factor)
				goto free_gate;

			fix_factor->mult = 1;
			fix_factor->div = data->div[i].fixed;

			rate_hw = &fix_factor->hw;
			rate_ops = &clk_fixed_factor_ops;
		} else {
			divider = kzalloc(sizeof(*divider), GFP_KERNEL);
			if (!divider)
				goto free_gate;

			flags = data->div[i].pow ? CLK_DIVIDER_POWER_OF_TWO : 0;

			divider->reg = reg;
			divider->shift = data->div[i].shift;
			divider->width = SUNXI_DIVISOR_WIDTH;
			divider->flags = flags;
			divider->lock = &clk_lock;
			divider->table = data->div[i].table;

			rate_hw = &divider->hw;
			rate_ops = &clk_divider_ops;
		}

		/* Wrap the (potential) gate and the divisor on a composite
		 * clock to unify them */
		clks[i] = clk_register_composite(NULL, clk_name, &parent, 1,
						 NULL, NULL,
						 rate_hw, rate_ops,
						 gate_hw, &clk_gate_ops,
						 clkflags |
						 data->div[i].critical ?
							CLK_IS_CRITICAL : 0);

		WARN_ON(IS_ERR(clk_data->clks[i]));
	}

	/* Adjust to the real max */
	clk_data->clk_num = i;

	if (of_clk_add_provider(node, of_clk_src_onecell_get, clk_data)) {
		pr_err("%s: failed to add clock provider for %s\n",
		       __func__, clk_name);
		goto free_gate;
	}

	return clks;
free_gate:
	kfree(gate);
free_clks:
	kfree(clks);
free_clkdata:
	kfree(clk_data);
out_unmap:
	iounmap(reg);
	return NULL;
}
