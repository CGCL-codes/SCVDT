function f0() {
    return Object.preventExtensions('a') === 'a';
}
if (!f0())
    throw new Error('Test failed');
