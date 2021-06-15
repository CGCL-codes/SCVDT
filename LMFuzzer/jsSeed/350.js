function f0() {
    return 'iterator' in Symbol;
}
if (!f0())
    throw new Error('Test failed');
