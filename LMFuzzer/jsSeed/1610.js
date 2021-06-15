function f0() {
    function f1() {
        Array(/x/.a = this) + '';
    }
    for (var v0 = 0; v0 < 1000; v0++)
        f1();
}
f0();
