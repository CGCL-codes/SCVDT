function f0() {
    return typeof Array.prototype[Symbol.iterator] === 'function';
}
if (!f0())
    throw new Error('Test failed');
