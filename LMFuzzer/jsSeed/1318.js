function f0() {
    return typeof String.fromCodePoint === 'function';
}
if (!f0())
    throw new Error('Test failed');
