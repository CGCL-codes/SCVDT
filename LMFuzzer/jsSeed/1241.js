function f0() {
    return typeof Math.tanh === 'function';
}
if (!f0())
    throw new Error('Test failed');
