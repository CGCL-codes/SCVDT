function f0() {
    var v0 = {};
    var v1 = new WeakSet();
    v1.add(v0);
    v1.add(v0);
    return v1.has(v0);
}
if (!f0())
    throw new Error('Test failed');
