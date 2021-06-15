function f0() {
    return String(Symbol('foo')) === 'Symbol(foo)';
}
if (!f0())
    throw new Error('Test failed');
