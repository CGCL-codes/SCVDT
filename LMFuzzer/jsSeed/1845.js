function f0() {
    return new Array();
}
var v0 = [];
for (var v1 = 0; v1 < 100000; ++v1)
    v0.push(f0());
for (var v1 = 0; v1 < 100000; ++v1) {
    if (v0[v1].length != 0)
        throw 'Error';
}
