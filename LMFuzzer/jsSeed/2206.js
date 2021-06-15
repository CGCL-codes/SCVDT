function f0() {
    return typeof Set.prototype.entries === 'function';
}
if (!f0())
    throw new Error('Test failed');
