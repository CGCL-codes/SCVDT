function f0() {
    return /\c2/.exec('\\c2')[0] === '\\c2';
}
if (!f0())
    throw new Error('Test failed');
