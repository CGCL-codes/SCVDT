function f0() {
    var v0 = function () {
        return z => arguments[0];
    }(5);
    return v0(6) === 5;
}
if (!f0())
    throw new Error('Test failed');
