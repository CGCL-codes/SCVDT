static int is_rndis(USBNetState *s)
{
    return s->dev.config ?
            s->dev.config->bConfigurationValue == DEV_RNDIS_CONFIG_VALUE : 0;
}
