function f0() {
    var v0;
    class C extends (v0 = class {
    }) {
    }
    return new C() instanceof v0 && v0.isPrototypeOf(C);
}
if (!f0())
    throw new Error('Test failed');
