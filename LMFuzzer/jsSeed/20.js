function f0() {
    class C extends Array {
    }
    var v0 = new C();
    return v0.concat(1) instanceof C;
}
if (!f0())
    throw new Error('Test failed');
