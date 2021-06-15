function f0() {
    return typeof Array.prototype.keys === 'function';
}
if (!f0())
    throw new Error('Test failed');
