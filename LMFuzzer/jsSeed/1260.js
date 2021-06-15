function f0() {
    return typeof WeakSet.prototype.delete === 'function';
}
if (!f0())
    throw new Error('Test failed');
