function f0(x) {
    return 0 > (Math.max(x, x) || x);
}
function f1() {
    return f0(f0() >> 0);
}
for (var v0 = 0; v0 < 1; ++v0) {
    f1();
}
