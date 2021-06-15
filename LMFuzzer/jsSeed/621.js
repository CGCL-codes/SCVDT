function f0() {
    class C {
        static foo() {
        }
    }
    ;
    return C.foo.name === 'foo';
}
if (!f0())
    throw new Error('Test failed');
