function f0() {
    return typeof Math.trunc === 'function';
}
if (!f0())
    throw new Error('Test failed');
