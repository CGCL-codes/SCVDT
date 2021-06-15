function f0() {
    return '\u20BB7'.match(/^.$/u)[0].length === 2;
}
if (!f0())
    throw new Error('Test failed');
