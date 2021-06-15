function f0() {
    class C extends Boolean {
    }
    var v0 = new C(true);
    return v0 instanceof Boolean && v0 == true;
}
if (!f0())
    throw new Error('Test failed');
