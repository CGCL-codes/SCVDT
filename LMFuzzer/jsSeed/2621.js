function f0() {
    return typeof Map.prototype[Symbol.iterator] === 'function';
}
if (!f0())
    throw new Error('Test failed');
