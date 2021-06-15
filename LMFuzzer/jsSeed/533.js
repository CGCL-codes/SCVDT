function f0() {
    class C extends Array {
    }
    return C.of(0) instanceof C;
}
if (!f0())
    throw new Error('Test failed');
