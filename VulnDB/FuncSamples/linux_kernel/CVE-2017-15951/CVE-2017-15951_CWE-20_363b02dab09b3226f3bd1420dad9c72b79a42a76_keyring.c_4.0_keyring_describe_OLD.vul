static void keyring_describe(const struct key *keyring, struct seq_file *m)
{
	if (keyring->description)
		seq_puts(m, keyring->description);
	else
		seq_puts(m, "[anon]");

	if (key_is_instantiated(keyring)) {
		if (keyring->keys.nr_leaves_on_tree != 0)
			seq_printf(m, ": %lu", keyring->keys.nr_leaves_on_tree);
		else
			seq_puts(m, ": empty");
	}
}
