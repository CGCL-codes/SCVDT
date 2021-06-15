function f0() {
    return typeof String.prototype[Symbol.iterator] === 'function';
}
if (!f0())
    throw new Error('Test failed');
