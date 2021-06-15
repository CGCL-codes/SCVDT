function f0() {
    return typeof Math.sign === 'function';
}
if (!f0())
    throw new Error('Test failed');
