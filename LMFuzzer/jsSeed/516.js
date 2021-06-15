function f0() {
    var v0 = new ArrayBuffer(64);
    var v1 = new DataView(v0);
    v1.setUint8(0, 256);
    return v1.getUint8(0) === 0;
}
if (!f0())
    throw new Error('Test failed');
