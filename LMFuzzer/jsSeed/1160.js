function f0() {
    return /[\w-_]/.exec('-')[0] === '-';
}
if (!f0())
    throw new Error('Test failed');
