function f0() {
    return /\u1/.exec('u1')[0] === 'u1' && /[\u1]/.exec('u')[0] === 'u';
}
if (!f0())
    throw new Error('Test failed');
