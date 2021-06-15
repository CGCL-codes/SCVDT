function f0() {
    return typeof Math.log1p === 'function';
}
if (!f0())
    throw new Error('Test failed');
