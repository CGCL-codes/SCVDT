function f0() {
    return new Function('a = 1', 'b = 2', 'return a === 3 && b === 2;')(3);
}
if (!f0())
    throw new Error('Test failed');
