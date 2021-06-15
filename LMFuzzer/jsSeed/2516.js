function f0() {
    class C extends Array {
    }
    var v0 = new C();
    return v0.filter(Boolean) instanceof C;
}
if (!f0())
    throw new Error('Test failed');
