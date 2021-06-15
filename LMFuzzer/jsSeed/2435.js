function f0() {
    return Object.freeze('a') === 'a';
}
if (!f0())
    throw new Error('Test failed');
