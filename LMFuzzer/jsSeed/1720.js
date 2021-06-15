function f0() {
    class C extends Array {
    }
    var v0 = new C();
    v0.push(2, 4, 6);
    return v0.splice(1, 2) instanceof C;
}
if (!f0())
    throw new Error('Test failed');
