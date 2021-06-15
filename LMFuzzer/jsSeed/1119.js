function f0() {
    var v0 = new ArrayBuffer(64);
    var v1 = new DataView(v0);
    v1.setInt16(0, 32768);
    return v1.getInt16(0) === -32768;
}
if (!f0())
    throw new Error('Test failed');
