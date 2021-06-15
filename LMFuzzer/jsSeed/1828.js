function f0() {
    var v0 = new WeakSet();
    var v1 = {};
    return v0.add(v1) === v0;
}
if (!f0())
    throw new Error('Test failed');
