function f0() {
    return typeof Math.expm1 === 'function';
}
if (!f0())
    throw new Error('Test failed');
