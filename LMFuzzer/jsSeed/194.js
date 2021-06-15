function f0() {
    return typeof Math.fround === 'function';
}
if (!f0())
    throw new Error('Test failed');
