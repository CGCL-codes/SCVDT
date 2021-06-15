function f0() {
    f1('hello');
    f1('hello');
    function f1(s) {
        v0 = Math.min(Math.max(Math.pow(-1, 0.5), 0), s.length);
        0 <= v0;
    }
}
f0();
