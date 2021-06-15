function f0() {
    return Object.seal('a') === 'a';
}
if (!f0())
    throw new Error('Test failed');
