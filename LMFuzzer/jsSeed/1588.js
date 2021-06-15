function f0() {
    return typeof Array.prototype.values === 'function';
}
if (!f0())
    throw new Error('Test failed');
