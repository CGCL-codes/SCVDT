static void mptsas_fetch_request(MPTSASState *s)
{
    PCIDevice *pci = (PCIDevice *) s;
    char req[MPTSAS_MAX_REQUEST_SIZE];
    MPIRequestHeader *hdr = (MPIRequestHeader *)req;
    hwaddr addr;
    int size;

    /* Read the message header from the guest first. */
    addr = s->host_mfa_high_addr | MPTSAS_FIFO_GET(s, request_post);
    pci_dma_read(pci, addr, req, sizeof(hdr));

    if (hdr->Function < ARRAY_SIZE(mpi_request_sizes) &&
        mpi_request_sizes[hdr->Function]) {
        /* Read the rest of the request based on the type.  Do not
         * reread everything, as that could cause a TOC/TOU mismatch
         * and leak data from the QEMU stack.
         */
        size = mpi_request_sizes[hdr->Function];
        assert(size <= MPTSAS_MAX_REQUEST_SIZE);
        pci_dma_read(pci, addr + sizeof(hdr), &req[sizeof(hdr)],
                     size - sizeof(hdr));
    }

    if (hdr->Function == MPI_FUNCTION_SCSI_IO_REQUEST) {
        /* SCSI I/O requests are separate from mptsas_process_message
         * because they cannot be sent through the doorbell yet.
         */
        mptsas_process_scsi_io_request(s, (MPIMsgSCSIIORequest *)req, addr);
    } else {
        mptsas_process_message(s, (MPIRequestHeader *)req);
    }
}
