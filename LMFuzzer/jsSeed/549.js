function f0() {
    class B {
    }
    class C extends B {
    }
    return new C() instanceof B && B.isPrototypeOf(C);
}
if (!f0())
    throw new Error('Test failed');
