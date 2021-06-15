function f0() {
    return /x{1/.exec('x{1')[0] === 'x{1' && /x]1/.exec('x]1')[0] === 'x]1';
}
if (!f0())
    throw new Error('Test failed');
