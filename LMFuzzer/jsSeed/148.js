function f0() {
    return typeof Array.prototype.find === 'function';
}
if (!f0())
    throw new Error('Test failed');
