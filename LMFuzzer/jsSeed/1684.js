function f0() {
    var v0 = Symbol.toStringTag;
    return Math[v0] === 'Math' && JSON[v0] === 'JSON';
}
if (!f0())
    throw new Error('Test failed');
