function f0() {
    return typeof Map.prototype.clear === 'function';
}
if (!f0())
    throw new Error('Test failed');
