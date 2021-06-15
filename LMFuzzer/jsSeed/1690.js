function f0() {
    return 'species' in Symbol;
}
if (!f0())
    throw new Error('Test failed');
