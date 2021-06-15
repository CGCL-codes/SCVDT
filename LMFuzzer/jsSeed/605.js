function f0() {
    function f1() {
        return f1;
    }
    function f2(a) {
        if (a) {
            throw 1;
        }
    }
    f2(f1());
}
try {
    f0();
} catch (e) {
}
