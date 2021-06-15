function f0() {
    var v0 = {};
    var v1 = new Map();
    v1.set(v0, 123);
    return v1.has(v0) && v1.get(v0) === 123;
}
if (!f0())
    throw new Error('Test failed');
