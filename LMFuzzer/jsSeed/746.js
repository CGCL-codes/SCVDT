function f0() {
    return typeof Set.prototype.forEach === 'function';
}
if (!f0())
    throw new Error('Test failed');
