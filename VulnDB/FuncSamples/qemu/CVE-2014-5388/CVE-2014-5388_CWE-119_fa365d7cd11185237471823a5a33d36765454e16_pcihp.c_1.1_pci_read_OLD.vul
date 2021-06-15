static uint64_t pci_read(void *opaque, hwaddr addr, unsigned int size)
{
    AcpiPciHpState *s = opaque;
    uint32_t val = 0;
    int bsel = s->hotplug_select;

    if (bsel < 0 || bsel > ACPI_PCIHP_MAX_HOTPLUG_BUS) {
        return 0;
    }

    switch (addr) {
    case PCI_UP_BASE:
        val = s->acpi_pcihp_pci_status[bsel].up;
        if (!s->legacy_piix) {
            s->acpi_pcihp_pci_status[bsel].up = 0;
        }
        ACPI_PCIHP_DPRINTF("pci_up_read %" PRIu32 "\n", val);
        break;
    case PCI_DOWN_BASE:
        val = s->acpi_pcihp_pci_status[bsel].down;
        ACPI_PCIHP_DPRINTF("pci_down_read %" PRIu32 "\n", val);
        break;
    case PCI_EJ_BASE:
        /* No feature defined yet */
        ACPI_PCIHP_DPRINTF("pci_features_read %" PRIu32 "\n", val);
        break;
    case PCI_RMV_BASE:
        val = s->acpi_pcihp_pci_status[bsel].hotplug_enable;
        ACPI_PCIHP_DPRINTF("pci_rmv_read %" PRIu32 "\n", val);
        break;
    case PCI_SEL_BASE:
        val = s->hotplug_select;
        ACPI_PCIHP_DPRINTF("pci_sel_read %" PRIu32 "\n", val);
    default:
        break;
    }

    return val;
}
