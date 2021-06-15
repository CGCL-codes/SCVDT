function f0() {
    class C {
        static method() {
            return this === undefined;
        }
    }
    return (0, C.method)();
}
if (!f0())
    throw new Error('Test failed');
