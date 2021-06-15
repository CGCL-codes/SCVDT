function f0() {
    return new Function().name === 'anonymous';
}
if (!f0())
    throw new Error('Test failed');
