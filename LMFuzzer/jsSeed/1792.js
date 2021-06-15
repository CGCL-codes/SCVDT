function f0() {
    return typeof String.raw === 'function';
}
if (!f0())
    throw new Error('Test failed');
