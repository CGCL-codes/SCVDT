function f0() {
    return typeof Array.prototype.fill === 'function';
}
if (!f0())
    throw new Error('Test failed');
