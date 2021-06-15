static void qemu_input_queue_process(void *opaque)
{
    struct QemuInputEventQueueHead *queue = opaque;
    QemuInputEventQueue *item;

    g_assert(!QTAILQ_EMPTY(queue));
    item = QTAILQ_FIRST(queue);
    g_assert(item->type == QEMU_INPUT_QUEUE_DELAY);
    QTAILQ_REMOVE(queue, item, node);
    g_free(item);

    while (!QTAILQ_EMPTY(queue)) {
        item = QTAILQ_FIRST(queue);
        switch (item->type) {
        case QEMU_INPUT_QUEUE_DELAY:
            timer_mod(item->timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                      + item->delay_ms);
            return;
        case QEMU_INPUT_QUEUE_EVENT:
            qemu_input_event_send(item->src, item->evt);
            qapi_free_InputEvent(item->evt);
            break;
        case QEMU_INPUT_QUEUE_SYNC:
            qemu_input_event_sync();
            break;
        }
        QTAILQ_REMOVE(queue, item, node);
        queue_count--;
        g_free(item);
    }
}
