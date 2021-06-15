function f0() {
    return typeof RegExp.prototype[Symbol.match] === 'function';
}
if (!f0())
    throw new Error('Test failed');
