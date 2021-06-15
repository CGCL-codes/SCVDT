static void vfio_msi_disable(struct vfio_pci_device *vdev, bool msix)
{
	struct pci_dev *pdev = vdev->pdev;
	int i;

	for (i = 0; i < vdev->num_ctx; i++) {
		vfio_virqfd_disable(&vdev->ctx[i].unmask);
		vfio_virqfd_disable(&vdev->ctx[i].mask);
	}

	vfio_msi_set_block(vdev, 0, vdev->num_ctx, NULL, msix);

	pci_free_irq_vectors(pdev);

	/*
	 * Both disable paths above use pci_intx_for_msi() to clear DisINTx
	 * via their shutdown paths.  Restore for NoINTx devices.
	 */
	if (vdev->nointx)
		pci_intx(pdev, 0);

	vdev->irq_type = VFIO_PCI_NUM_IRQS;
	vdev->num_ctx = 0;
	kfree(vdev->ctx);
}
