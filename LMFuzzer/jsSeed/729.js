function f0() {
    return '\u10418'.toLowerCase() === '\u10440' && '\u10440'.toUpperCase() === '\u10418';
}
if (!f0())
    throw new Error('Test failed');
