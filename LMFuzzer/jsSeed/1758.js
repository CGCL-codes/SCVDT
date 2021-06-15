function f0() {
    return typeof String.prototype.repeat === 'function' && 'foo'.repeat(3) === 'foofoofoo';
}
if (!f0())
    throw new Error('Test failed');
