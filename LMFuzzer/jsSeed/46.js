function f0() {
    var v0 = Object.freeze({});
    var v1 = new WeakMap();
    v1.set(v0, 42);
    return v1.get(v0) === 42;
}
if (!f0())
    throw new Error('Test failed');
