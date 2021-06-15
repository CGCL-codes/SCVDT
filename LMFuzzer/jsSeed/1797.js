function f0() {
}
function f1(v0) {
    try {
        f2(v0);
    } catch (e) {
    }
}
function f2(v0) {
    if (f0() != v0 || v0)
        throw v0 = 'foo';
    return v0;
}
f1(3);
f1(NaN);
