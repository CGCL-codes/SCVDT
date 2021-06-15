function f0(x, y) {
    return Math.imul(0, Math.imul(y | 0, x >> 0));
}
for (var v0 = 0; v0 < 2; v0++) {
    try {
        f0(1 ? 0 : undefined)();
    } catch (e) {
    }
}
