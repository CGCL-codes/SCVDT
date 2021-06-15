function f0() {
    return /\x1/.exec('x1')[0] === 'x1' && /[\x1]/.exec('x')[0] === 'x';
}
if (!f0())
    throw new Error('Test failed');
