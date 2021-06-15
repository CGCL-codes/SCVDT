function f0() {
    class R extends RegExp {
    }
    var v0 = new R('baz', 'g');
    return v0.global && v0.source === 'baz';
}
if (!f0())
    throw new Error('Test failed');
