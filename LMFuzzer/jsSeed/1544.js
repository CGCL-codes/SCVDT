function f0() {
    var v0 = {};
    class S extends Set {
    }
    var v1 = new S();
    v1.add(123);
    v1.add(123);
    return v1.has(123);
}
if (!f0())
    throw new Error('Test failed');
