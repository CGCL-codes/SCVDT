function f0() {
    var v0 = x => x + 'foo';
    return v0('fee fie foe ') === 'fee fie foe foo';
}
if (!f0())
    throw new Error('Test failed');
