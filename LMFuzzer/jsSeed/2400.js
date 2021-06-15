function f0() {
    class C extends Array {
    }
    return Array.isArray(new C());
}
if (!f0())
    throw new Error('Test failed');
