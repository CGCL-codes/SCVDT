function f0() {
    var v0 = new ArrayBuffer(64);
    var v1 = new Uint8ClampedArray(v0);
    v1[0] = 256;
    return v1[0] === 255;
}
if (!f0())
    throw new Error('Test failed');
