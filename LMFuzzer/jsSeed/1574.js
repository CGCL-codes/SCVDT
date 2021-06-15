function f0() {
    return typeof Math.atanh === 'function';
}
if (!f0())
    throw new Error('Test failed');
