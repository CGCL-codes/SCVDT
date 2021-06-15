function f0() {
    for (var [i, j, k] in { qux: 1 }) {
        return i === 'q' && j === 'u' && k === 'x';
    }
}
if (!f0())
    throw new Error('Test failed');
