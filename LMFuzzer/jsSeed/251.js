var v0 = new Int8Array(new ArrayBuffer(100));
function f0(v1) {
    return v0[v1];
}
for (var v1 = 0; v1 < 100000; ++v1) {
    if (f0(v1 % 100) != 0)
        throw 'Error';
}
