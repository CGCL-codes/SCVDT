function f0() {
    var v0 = {};
    var v1 = new Set();
    v1.add(123);
    v1.add(123);
    v1.add(456);
    return v1.size === 2;
}
if (!f0())
    throw new Error('Test failed');
