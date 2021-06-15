function f0() {
    new Function('function ff () { actual = \'\' + ff. caller; } function f () { ff (); } f ();')('function pf' + f0 + '() {}');
}
f0();
