var v0 = new Int8Array(new ArrayBuffer(100));
function f0() {
    return v0[0];
}
for (var v1 = 0; v1 < 100000; ++v1) {
    if (f0() != 0)
        throw 'Error';
}
