function f0() {
    function f1(a, b) {
    }
    function f2() {
        for (var v0 = 0; v0 < 1; ++v0) {
            f1(32768, f1());
        }
    }
    f2();
}
f0();
