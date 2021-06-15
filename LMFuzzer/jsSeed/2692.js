function f0() {
    class C extends Array {
    }
    var v0 = new C();
    v0[2] = 'foo';
    v0.length = 1;
    return v0.length === 1 && !(2 in v0);
}
if (!f0())
    throw new Error('Test failed');
