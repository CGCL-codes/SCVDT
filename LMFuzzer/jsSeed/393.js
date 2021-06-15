function f0() {
    return /./igm.flags === 'gim' && /./.flags === '';
}
if (!f0())
    throw new Error('Test failed');
