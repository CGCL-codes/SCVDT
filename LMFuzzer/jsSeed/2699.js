function f0() {
    var v0 = '';
    for (var v1 of 'foo')
        v0 += v1;
    return v0 === 'foo';
}
if (!f0())
    throw new Error('Test failed');
