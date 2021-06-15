function f0() {
    return 2 === 2 && 2 === 2;
}
if (!f0())
    throw new Error('Test failed');
