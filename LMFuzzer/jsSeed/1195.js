function f0() {
    var v0 = 'corge';
    var {[qux]: grault} = { corge: 'garply' };
    return grault === 'garply';
}
if (!f0())
    throw new Error('Test failed');
