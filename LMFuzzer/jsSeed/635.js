function f0() {
    var v0 = new ArrayBuffer(64);
    var v1 = new DataView(v0);
    v1.setFloat64(0, 0.1);
    return v1.getFloat64(0) === 0.1;
}
if (!f0())
    throw new Error('Test failed');
