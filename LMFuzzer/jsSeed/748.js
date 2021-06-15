function f0() {
    return typeof Map.prototype.delete === 'function';
}
if (!f0())
    throw new Error('Test failed');
