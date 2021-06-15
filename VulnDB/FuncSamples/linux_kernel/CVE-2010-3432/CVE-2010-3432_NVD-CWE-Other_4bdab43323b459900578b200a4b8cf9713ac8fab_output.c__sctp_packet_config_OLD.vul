struct sctp_packet *sctp_packet_config(struct sctp_packet *packet,
				       __u32 vtag, int ecn_capable)
{
	struct sctp_chunk *chunk = NULL;

	SCTP_DEBUG_PRINTK("%s: packet:%p vtag:0x%x\n", __func__,
			  packet, vtag);

	sctp_packet_reset(packet);
	packet->vtag = vtag;

	if (ecn_capable && sctp_packet_empty(packet)) {
		chunk = sctp_get_ecne_prepend(packet->transport->asoc);

		/* If there a is a prepend chunk stick it on the list before
		 * any other chunks get appended.
		 */
		if (chunk)
			sctp_packet_append_chunk(packet, chunk);
	}

	return packet;
}
