function f0() {
    return Array.from({
        0: 'foo',
        1: 'bar',
        length: 2
    }) + '' === 'foo,bar';
}
if (!f0())
    throw new Error('Test failed');
