function f0() {
    var v0 = function* () {
        yield 1;
        yield 2;
        yield 3;
    }();
    return Math.max(...v0) === 3;
}
if (!f0())
    throw new Error('Test failed');
