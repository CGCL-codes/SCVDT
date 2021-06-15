function f0() {
    return typeof Symbol() === 'symbol';
}
if (!f0())
    throw new Error('Test failed');
