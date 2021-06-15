function f0(f) {
    for (var v0 = 0; v0 < 999; ++v0) {
        f(0 / 0);
    }
}
function f1(x) {
    x < 1 ? 0 : Math.imul(x || 0);
}
f0(f1);
