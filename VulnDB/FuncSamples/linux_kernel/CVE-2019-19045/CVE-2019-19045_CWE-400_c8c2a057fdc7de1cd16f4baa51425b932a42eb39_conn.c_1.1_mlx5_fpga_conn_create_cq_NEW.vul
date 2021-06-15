static int mlx5_fpga_conn_create_cq(struct mlx5_fpga_conn *conn, int cq_size)
{
	struct mlx5_fpga_device *fdev = conn->fdev;
	struct mlx5_core_dev *mdev = fdev->mdev;
	u32 temp_cqc[MLX5_ST_SZ_DW(cqc)] = {0};
	u32 out[MLX5_ST_SZ_DW(create_cq_out)];
	struct mlx5_wq_param wqp;
	struct mlx5_cqe64 *cqe;
	int inlen, err, eqn;
	unsigned int irqn;
	void *cqc, *in;
	__be64 *pas;
	u32 i;

	cq_size = roundup_pow_of_two(cq_size);
	MLX5_SET(cqc, temp_cqc, log_cq_size, ilog2(cq_size));

	wqp.buf_numa_node = mdev->priv.numa_node;
	wqp.db_numa_node  = mdev->priv.numa_node;

	err = mlx5_cqwq_create(mdev, &wqp, temp_cqc, &conn->cq.wq,
			       &conn->cq.wq_ctrl);
	if (err)
		return err;

	for (i = 0; i < mlx5_cqwq_get_size(&conn->cq.wq); i++) {
		cqe = mlx5_cqwq_get_wqe(&conn->cq.wq, i);
		cqe->op_own = MLX5_CQE_INVALID << 4 | MLX5_CQE_OWNER_MASK;
	}

	inlen = MLX5_ST_SZ_BYTES(create_cq_in) +
		sizeof(u64) * conn->cq.wq_ctrl.buf.npages;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_cqwq;
	}

	err = mlx5_vector2eqn(mdev, smp_processor_id(), &eqn, &irqn);
	if (err) {
		kvfree(in);
		goto err_cqwq;
	}

	cqc = MLX5_ADDR_OF(create_cq_in, in, cq_context);
	MLX5_SET(cqc, cqc, log_cq_size, ilog2(cq_size));
	MLX5_SET(cqc, cqc, c_eqn, eqn);
	MLX5_SET(cqc, cqc, uar_page, fdev->conn_res.uar->index);
	MLX5_SET(cqc, cqc, log_page_size, conn->cq.wq_ctrl.buf.page_shift -
			   MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET64(cqc, cqc, dbr_addr, conn->cq.wq_ctrl.db.dma);

	pas = (__be64 *)MLX5_ADDR_OF(create_cq_in, in, pas);
	mlx5_fill_page_frag_array(&conn->cq.wq_ctrl.buf, pas);

	err = mlx5_core_create_cq(mdev, &conn->cq.mcq, in, inlen, out, sizeof(out));
	kvfree(in);

	if (err)
		goto err_cqwq;

	conn->cq.mcq.cqe_sz     = 64;
	conn->cq.mcq.set_ci_db  = conn->cq.wq_ctrl.db.db;
	conn->cq.mcq.arm_db     = conn->cq.wq_ctrl.db.db + 1;
	*conn->cq.mcq.set_ci_db = 0;
	*conn->cq.mcq.arm_db    = 0;
	conn->cq.mcq.vector     = 0;
	conn->cq.mcq.comp       = mlx5_fpga_conn_cq_complete;
	conn->cq.mcq.event      = mlx5_fpga_conn_cq_event;
	conn->cq.mcq.irqn       = irqn;
	conn->cq.mcq.uar        = fdev->conn_res.uar;
	tasklet_init(&conn->cq.tasklet, mlx5_fpga_conn_cq_tasklet,
		     (unsigned long)conn);

	mlx5_fpga_dbg(fdev, "Created CQ #0x%x\n", conn->cq.mcq.cqn);

	goto out;

err_cqwq:
	mlx5_wq_destroy(&conn->cq.wq_ctrl);
out:
	return err;
}
