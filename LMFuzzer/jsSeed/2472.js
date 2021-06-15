function f0() {
    return typeof Math.cosh === 'function';
}
if (!f0())
    throw new Error('Test failed');
