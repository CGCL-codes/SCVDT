function f0() {
    class R extends RegExp {
    }
    var v0 = new R('baz');
    return v0.test('foobarbaz');
}
if (!f0())
    throw new Error('Test failed');
