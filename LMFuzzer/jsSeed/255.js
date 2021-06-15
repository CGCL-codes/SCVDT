function f0() {
    return typeof Math.imul === 'function';
}
if (!f0())
    throw new Error('Test failed');
