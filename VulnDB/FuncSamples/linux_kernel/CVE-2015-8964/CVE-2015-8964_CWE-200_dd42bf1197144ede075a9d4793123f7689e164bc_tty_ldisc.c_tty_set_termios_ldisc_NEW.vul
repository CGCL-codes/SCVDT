static void tty_set_termios_ldisc(struct tty_struct *tty, int num)
{
	down_write(&tty->termios_rwsem);
	tty->termios.c_line = num;
	up_write(&tty->termios_rwsem);

	tty->disc_data = NULL;
	tty->receive_room = 0;
}
