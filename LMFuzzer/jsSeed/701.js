function f0() {
    return typeof Set.prototype.keys === 'function';
}
if (!f0())
    throw new Error('Test failed');
