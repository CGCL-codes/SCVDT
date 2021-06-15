function f0() {
    var v0 = new WeakMap();
    var v1 = {};
    return v0.set(v1, 0) === v0;
}
if (!f0())
    throw new Error('Test failed');
