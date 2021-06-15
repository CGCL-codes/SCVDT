function f0() {
    var v0 = new ArrayBuffer(64);
    var v1 = new Float32Array(v0);
    v1[0] = 0.1;
    return v1[0] === 0.10000000149011612;
}
if (!f0())
    throw new Error('Test failed');
