function f0() {
    var v0 = new ArrayBuffer(64);
    var v1 = new Uint8Array(v0);
    v1[0] = 256;
    return v1[0] === 0;
}
if (!f0())
    throw new Error('Test failed');
