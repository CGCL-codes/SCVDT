function f0() {
    class C {
        foo() {
        }
    }
    ;
    return new C().foo.name === 'foo';
}
if (!f0())
    throw new Error('Test failed');
