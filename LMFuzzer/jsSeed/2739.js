function f0() {
    return typeof Set.prototype[Symbol.iterator] === 'function';
}
if (!f0())
    throw new Error('Test failed');
