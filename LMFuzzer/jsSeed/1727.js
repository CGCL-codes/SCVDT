function f0(x) {
    x((x | 0) + x);
}
;
try {
    f0(1);
} catch (e) {
}
for (var v0 = 0; v0 < 1; ++v0) {
    try {
        f0(Symbol());
    } catch (e) {
    }
}
