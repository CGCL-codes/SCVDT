function f0() {
    var v0 = new ArrayBuffer(64);
    var v1 = new Int8Array(v0);
    v1[0] = 128;
    return v1[0] === -128;
}
if (!f0())
    throw new Error('Test failed');
