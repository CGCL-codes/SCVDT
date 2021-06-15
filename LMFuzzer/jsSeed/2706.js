function f0() {
    var v0 = new ArrayBuffer(64);
    var v1 = new Int32Array(v0);
    v1[0] = 2147483648;
    return v1[0] === -2147483648;
}
if (!f0())
    throw new Error('Test failed');
