function f0() {
    return typeof Set.prototype.delete === 'function';
}
if (!f0())
    throw new Error('Test failed');
