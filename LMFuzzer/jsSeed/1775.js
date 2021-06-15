function f0() {
    class C extends Number {
    }
    var v0 = new C(6);
    return v0 instanceof Number && +v0 === 6;
}
if (!f0())
    throw new Error('Test failed');
