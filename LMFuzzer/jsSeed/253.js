function f0() {
    return Object.isFrozen('a') === true;
}
if (!f0())
    throw new Error('Test failed');
