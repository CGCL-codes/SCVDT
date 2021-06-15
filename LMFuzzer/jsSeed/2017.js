function f0() {
    return typeof RegExp.prototype.compile === 'function';
}
if (!f0())
    throw new Error('Test failed');
