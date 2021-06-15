function f0() {
    var v0 = new ArrayBuffer(64);
    var v1 = new Uint32Array(v0);
    v1[0] = 4294967296;
    return v1[0] === 0;
}
if (!f0())
    throw new Error('Test failed');
