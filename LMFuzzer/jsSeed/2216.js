function f0() {
    return typeof Map.prototype.keys === 'function';
}
if (!f0())
    throw new Error('Test failed');
