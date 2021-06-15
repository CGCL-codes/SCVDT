function f0() {
    return typeof Set.prototype.clear === 'function';
}
if (!f0())
    throw new Error('Test failed');
