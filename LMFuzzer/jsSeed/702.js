function f0() {
    return [
        'a',
        ...'bcd',
        'e'
    ][3] === 'd';
}
if (!f0())
    throw new Error('Test failed');
