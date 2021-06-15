function f0() {
    return typeof WeakMap.prototype.delete === 'function';
}
if (!f0())
    throw new Error('Test failed');
