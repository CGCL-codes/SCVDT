function f0(x, expected) {
    var v0 = [];
    v0.length = x;
    f0(true, 1);
}
try {
    f0(2147483648, 2147483648);
} catch (e) {
}
