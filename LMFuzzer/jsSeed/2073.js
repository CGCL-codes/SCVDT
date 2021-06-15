function f0() {
    var v0 = new ArrayBuffer(64);
    var v1 = new DataView(v0);
    v1.setInt8(0, 128);
    return v1.getInt8(0) === -128;
}
if (!f0())
    throw new Error('Test failed');
