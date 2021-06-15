function f0() {
    return typeof Map.prototype.values === 'function';
}
if (!f0())
    throw new Error('Test failed');
