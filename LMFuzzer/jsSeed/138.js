function f0() {
    return Object.isSealed('a') === true;
}
if (!f0())
    throw new Error('Test failed');
