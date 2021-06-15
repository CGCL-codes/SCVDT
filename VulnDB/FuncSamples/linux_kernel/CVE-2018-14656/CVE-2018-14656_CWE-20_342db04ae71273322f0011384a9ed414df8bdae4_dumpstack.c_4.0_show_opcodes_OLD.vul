void show_opcodes(u8 *rip, const char *loglvl)
{
#define PROLOGUE_SIZE 42
#define EPILOGUE_SIZE 21
#define OPCODE_BUFSIZE (PROLOGUE_SIZE + 1 + EPILOGUE_SIZE)
	u8 opcodes[OPCODE_BUFSIZE];

	if (probe_kernel_read(opcodes, rip - PROLOGUE_SIZE, OPCODE_BUFSIZE)) {
		printk("%sCode: Bad RIP value.\n", loglvl);
	} else {
		printk("%sCode: %" __stringify(PROLOGUE_SIZE) "ph <%02x> %"
		       __stringify(EPILOGUE_SIZE) "ph\n", loglvl, opcodes,
		       opcodes[PROLOGUE_SIZE], opcodes + PROLOGUE_SIZE + 1);
	}
}
