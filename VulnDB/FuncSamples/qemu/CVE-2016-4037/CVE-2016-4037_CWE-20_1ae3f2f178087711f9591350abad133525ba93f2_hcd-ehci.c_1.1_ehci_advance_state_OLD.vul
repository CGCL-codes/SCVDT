static void ehci_advance_state(EHCIState *ehci, int async)
{
    EHCIQueue *q = NULL;
    int again;

    do {
        switch(ehci_get_state(ehci, async)) {
        case EST_WAITLISTHEAD:
            again = ehci_state_waitlisthead(ehci, async);
            break;

        case EST_FETCHENTRY:
            again = ehci_state_fetchentry(ehci, async);
            break;

        case EST_FETCHQH:
            q = ehci_state_fetchqh(ehci, async);
            if (q != NULL) {
                assert(q->async == async);
                again = 1;
            } else {
                again = 0;
            }
            break;

        case EST_FETCHITD:
            again = ehci_state_fetchitd(ehci, async);
            break;

        case EST_FETCHSITD:
            again = ehci_state_fetchsitd(ehci, async);
            break;

        case EST_ADVANCEQUEUE:
            assert(q != NULL);
            again = ehci_state_advqueue(q);
            break;

        case EST_FETCHQTD:
            assert(q != NULL);
            again = ehci_state_fetchqtd(q);
            break;

        case EST_HORIZONTALQH:
            assert(q != NULL);
            again = ehci_state_horizqh(q);
            break;

        case EST_EXECUTE:
            assert(q != NULL);
            again = ehci_state_execute(q);
            if (async) {
                ehci->async_stepdown = 0;
            }
            break;

        case EST_EXECUTING:
            assert(q != NULL);
            if (async) {
                ehci->async_stepdown = 0;
            }
            again = ehci_state_executing(q);
            break;

        case EST_WRITEBACK:
            assert(q != NULL);
            again = ehci_state_writeback(q);
            if (!async) {
                ehci->periodic_sched_active = PERIODIC_ACTIVE;
            }
            break;

        default:
            fprintf(stderr, "Bad state!\n");
            again = -1;
            g_assert_not_reached();
            break;
        }

        if (again < 0) {
            fprintf(stderr, "processing error - resetting ehci HC\n");
            ehci_reset(ehci);
            again = 0;
        }
    }
    while (again);
}
