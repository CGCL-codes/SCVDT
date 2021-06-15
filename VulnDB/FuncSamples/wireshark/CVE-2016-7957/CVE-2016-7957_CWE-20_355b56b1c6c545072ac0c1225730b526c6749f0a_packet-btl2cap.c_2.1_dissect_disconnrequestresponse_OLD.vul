static int
dissect_disconnrequestresponse(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree, proto_tree *command_tree, bthci_acl_data_t *acl_data, btl2cap_data_t *l2cap_data,
        gboolean is_request)
{
    guint16       scid;
    guint16       dcid;
    guint         psm = 0;
    const gchar  *service_name = "Unknown";

    dcid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(command_tree, hf_btl2cap_dcid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    scid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(command_tree, hf_btl2cap_scid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (!pinfo->fd->flags.visited) {
        psm_data_t        *psm_data;
        wmem_tree_key_t    key[6];
        guint32            k_interface_id;
        guint32            k_adapter_id;
        guint32            k_chandle;
        guint32            k_cid;
        guint32            k_frame_number;
        guint32            interface_id;
        guint32            adapter_id;
        guint32            chandle;
        guint32            key_scid;
        guint32            key_dcid;

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            interface_id = pinfo->phdr->interface_id;
        else
            interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = (acl_data) ? acl_data->adapter_id : HCI_ADAPTER_DEFAULT;
        chandle      = (acl_data) ? acl_data->chandle : 0;
        if ((is_request && pinfo->p2p_dir == P2P_DIR_SENT) ||
                (!is_request && pinfo->p2p_dir == P2P_DIR_RECV)) {
            key_dcid     = dcid | 0x80000000;
            key_scid     = scid;
        } else {
            key_dcid     = scid | 0x80000000;
            key_scid     = dcid;
        }

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = key_dcid;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        psm_data = (psm_data_t *)wmem_tree_lookup32_array_le(cid_to_psm_table, key);
        if (psm_data && psm_data->interface_id == interface_id &&
                psm_data->adapter_id == adapter_id &&
                psm_data->chandle == chandle &&
                psm_data->remote_cid == key_dcid &&
                psm_data->disconnect_in_frame == max_disconnect_in_frame) {
            psm_data->disconnect_in_frame = pinfo->num;
        }

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = key_scid;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        psm_data = (psm_data_t *)wmem_tree_lookup32_array_le(cid_to_psm_table, key);
        if (psm_data && psm_data->interface_id == interface_id &&
                psm_data->adapter_id == adapter_id &&
                psm_data->chandle == chandle &&
                psm_data->local_cid == key_scid &&
                psm_data->disconnect_in_frame == max_disconnect_in_frame) {
            psm_data->disconnect_in_frame = pinfo->num;
        }
    }

    if (l2cap_data) {
        proto_item        *sub_item;
        guint32            bt_uuid = 0;
        guint32            connect_in_frame = 0;
        psm_data_t        *psm_data;
        wmem_tree_key_t    key[6];
        guint32            k_interface_id;
        guint32            k_adapter_id;
        guint32            k_chandle;
        guint32            k_cid;
        guint32            k_frame_number;
        guint32            interface_id;
        guint32            adapter_id;
        guint32            chandle;
        guint32            key_dcid;

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            interface_id = pinfo->phdr->interface_id;
        else
            interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = (acl_data) ? acl_data->adapter_id : HCI_ADAPTER_DEFAULT;
        chandle      = (acl_data) ? acl_data->chandle : 0;
        if ((is_request && pinfo->p2p_dir == P2P_DIR_SENT) ||
                (!is_request && pinfo->p2p_dir == P2P_DIR_RECV)) {
            key_dcid     = dcid | 0x80000000;
        } else {
            key_dcid     = scid | 0x80000000;
        }

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = key_dcid;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        psm_data = (psm_data_t *)wmem_tree_lookup32_array_le(cid_to_psm_table, key);
        if (psm_data && psm_data->interface_id == interface_id &&
                psm_data->adapter_id == adapter_id &&
                psm_data->chandle == chandle &&
                psm_data->remote_cid == key_dcid) {
            psm = psm_data->psm;
            bt_uuid = get_service_uuid(pinfo, l2cap_data, psm_data->psm, psm_data->local_service);
            connect_in_frame = psm_data->connect_in_frame;
        }

        if (bt_uuid) {
            bluetooth_uuid_t   uuid;

            uuid.size = 2;
            uuid.bt_uuid = bt_uuid;
            uuid.data[0] = bt_uuid >> 8;
            uuid.data[1] = bt_uuid & 0xFF;

            service_name = val_to_str_ext_const(uuid.bt_uuid, &bluetooth_uuid_vals_ext, "Unknown");
        }

        if (memcmp(service_name, "Unknown", 7) == 0) {
            service_name = val_to_str_const(psm, psm_vals, "Unknown");
        }

        if (psm > 0) {
            sub_item = proto_tree_add_uint(tree, hf_btl2cap_psm, tvb, offset, 0, psm);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }

        if (bt_uuid) {
            sub_item = proto_tree_add_uint(tree, hf_btl2cap_service, tvb, 0, 0, bt_uuid);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }

        if (connect_in_frame > 0) {
            sub_item = proto_tree_add_uint(tree, hf_btl2cap_connect_in_frame, tvb, 0, 0, connect_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }
    }

    if (psm > 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (SCID: 0x%04x, DCID: 0x%04x, PSM: 0x%04x, Service: %s)", scid, dcid, psm, service_name);
    else
        col_append_fstr(pinfo->cinfo, COL_INFO, " (SCID: 0x%04x, DCID: 0x%04x, PSM: Unknown, Service: %s)", scid, dcid, service_name);


    return offset;
}
