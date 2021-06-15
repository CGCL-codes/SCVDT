function f0() {
    return (() => 5)() === 5;
}
if (!f0())
    throw new Error('Test failed');
