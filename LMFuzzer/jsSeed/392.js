function f0() {
    return Number('0o1') === 1;
}
if (!f0())
    throw new Error('Test failed');
