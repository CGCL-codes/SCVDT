function f0() {
    function f1() {
    }
    v0 = [
        new function f1() {
            f1 += '' + f0;
        }(),
        new f1()
    ];
}
f0();
