function f0() {
    return typeof Math.sinh === 'function';
}
if (!f0())
    throw new Error('Test failed');
