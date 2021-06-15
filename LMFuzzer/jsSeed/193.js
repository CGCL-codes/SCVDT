function f0() {
    class C extends Function {
    }
    var v0 = new C('return \'foo\';');
    return v0() === 'foo';
}
if (!f0())
    throw new Error('Test failed');
