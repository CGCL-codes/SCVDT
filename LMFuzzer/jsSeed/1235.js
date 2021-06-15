function f0() {
    return typeof Array.prototype.entries === 'function';
}
if (!f0())
    throw new Error('Test failed');
