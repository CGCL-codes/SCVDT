function f0() {
    var v0 = {};
    v0[Symbol.toStringTag] = 'foo';
    return v0 + '' === '[object foo]';
}
if (!f0())
    throw new Error('Test failed');
