function f0() {
    return Number('0b1') === 1;
}
if (!f0())
    throw new Error('Test failed');
