function f0() {
    return 8 === 8 && 8 === 8;
}
if (!f0())
    throw new Error('Test failed');
