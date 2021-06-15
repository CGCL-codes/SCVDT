function f0() {
    return Object.getOwnPropertyNames(Object.prototype).indexOf('__proto__') > -1;
}
if (!f0())
    throw new Error('Test failed');
