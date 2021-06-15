function f0() {
    with (f0)
        eval('arguments[0]');
}
f0();
