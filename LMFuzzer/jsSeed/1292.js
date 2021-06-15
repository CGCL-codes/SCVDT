function f0() {
    class R extends RegExp {
    }
    var v0 = new R('baz', 'g');
    return v0.exec('foobarbaz')[0] === 'baz' && v0.lastIndex === 9;
}
if (!f0())
    throw new Error('Test failed');
