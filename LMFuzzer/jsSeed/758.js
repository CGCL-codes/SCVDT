function f0() {
    return /\z/.exec('\\z')[0] === 'z' && /[\z]/.exec('[\\z]')[0] === 'z';
}
if (!f0())
    throw new Error('Test failed');
