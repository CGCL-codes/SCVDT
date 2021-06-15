function f0() {
    var v0 = {
        foo() {
        }
    };
    return v0.foo.name === 'foo';
}
if (!f0())
    throw new Error('Test failed');
