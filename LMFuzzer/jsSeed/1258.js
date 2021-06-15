function f0() {
    return typeof Map.prototype.entries === 'function';
}
if (!f0())
    throw new Error('Test failed');
