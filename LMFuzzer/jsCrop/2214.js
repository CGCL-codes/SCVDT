function f0() {
    return [...'\u20BB7\u20BB6'][0] === '\u20BB7';
}
if (!f0())
    throw new Error('Test failed');
