void acpi_gpe_init(ACPIREGS *ar, uint8_t len)
{
    ar->gpe.len = len;
    ar->gpe.sts = g_malloc0(len / 2);
    ar->gpe.en = g_malloc0(len / 2);
}
