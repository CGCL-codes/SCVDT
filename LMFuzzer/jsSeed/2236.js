function f0() {
    return '\u1D306'.match(/\u{1d306}/u)[0].length === 2;
}
if (!f0())
    throw new Error('Test failed');
