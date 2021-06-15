function f0() {
    return typeof Array.prototype.copyWithin === 'function';
}
if (!f0())
    throw new Error('Test failed');
