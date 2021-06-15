function f0() {
    return Object.prototype.hasOwnProperty('__proto__');
}
if (!f0())
    throw new Error('Test failed');
