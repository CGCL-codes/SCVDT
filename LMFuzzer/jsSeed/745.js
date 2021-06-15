function f0() {
    return typeof String.prototype.codePointAt === 'function';
}
if (!f0())
    throw new Error('Test failed');
