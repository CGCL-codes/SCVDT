function f0() {
    return new Array();
}
function f1() {
    for (var v0 = 0; v0 < 10000000; ++v0)
        f0();
}
f1();
