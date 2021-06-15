function f0() {
    var v0 = {};
    var v1 = {};
    var v2 = new Set([
        v0,
        v1
    ]);
    return v2.has(v0) && v2.has(v1);
}
if (!f0())
    throw new Error('Test failed');
