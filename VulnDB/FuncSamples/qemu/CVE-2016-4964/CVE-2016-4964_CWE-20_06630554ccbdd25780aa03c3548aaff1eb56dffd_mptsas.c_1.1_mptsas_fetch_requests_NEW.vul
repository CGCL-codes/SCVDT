static void mptsas_fetch_requests(void *opaque)
{
    MPTSASState *s = opaque;

    if (s->state != MPI_IOC_STATE_OPERATIONAL) {
        mptsas_set_fault(s, MPI_IOCSTATUS_INVALID_STATE);
        return;
    }
    while (!MPTSAS_FIFO_EMPTY(s, request_post)) {
        mptsas_fetch_request(s);
    }
}
