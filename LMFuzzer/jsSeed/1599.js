function f0() {
    return typeof Math.cbrt === 'function';
}
if (!f0())
    throw new Error('Test failed');
