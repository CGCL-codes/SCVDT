var v0 = -0.75;
function f0() {
    return Math.abs(v0);
}
for (var v1 = 0; v1 < 10000; v1++) {
    var v2 = f0();
    if (v2 < 0)
        throw 'Error: Math.abs returned a negative value.';
}
