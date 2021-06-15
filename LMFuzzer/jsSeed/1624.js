function f0() {
    return typeof Math.asinh === 'function';
}
if (!f0())
    throw new Error('Test failed');
