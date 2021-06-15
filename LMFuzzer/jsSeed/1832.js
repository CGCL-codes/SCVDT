function f0() {
    return typeof Set.prototype.values === 'function';
}
if (!f0())
    throw new Error('Test failed');
