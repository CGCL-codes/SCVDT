function f0() {
    return Object.isExtensible('a') === false;
}
if (!f0())
    throw new Error('Test failed');
