function f0() {
    return typeof Array.of === 'function' && Array.of(2)[0] === 2;
}
if (!f0())
    throw new Error('Test failed');
