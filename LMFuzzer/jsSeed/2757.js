function f0() {
    return 0;
}
function f1() {
    for (var v0 = 0; v0 < 100; v0++) {
        f0(0);
        f0(0);
    }
}
f1();
