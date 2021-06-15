function f0() {
    var v0 = {};
    var v1 = new Map();
    v1.set(v0, 123);
    return v1.size === 1;
}
if (!f0())
    throw new Error('Test failed');
