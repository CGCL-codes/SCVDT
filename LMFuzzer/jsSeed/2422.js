function f0() {
    return function ({a, b}, [c, d]) {
    }.length === 2;
}
if (!f0())
    throw new Error('Test failed');
