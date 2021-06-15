function f0() {
    var v0 = new ArrayBuffer(64);
    var v1 = new DataView(v0);
    v1.setUint32(0, 4294967296);
    return v1.getUint32(0) === 0;
}
if (!f0())
    throw new Error('Test failed');
