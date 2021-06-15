function f0() {
    return typeof Math.clz32 === 'function';
}
if (!f0())
    throw new Error('Test failed');
