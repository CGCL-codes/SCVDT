function f0() {
    return Math.max(...'1234') === 4;
}
if (!f0())
    throw new Error('Test failed');
