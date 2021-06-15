function f0() {
    return typeof Math.log2 === 'function';
}
if (!f0())
    throw new Error('Test failed');
