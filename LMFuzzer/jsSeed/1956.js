function f0() {
    return typeof Array.prototype.findIndex === 'function';
}
if (!f0())
    throw new Error('Test failed');
