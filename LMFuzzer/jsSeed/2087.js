function f0() {
    var v0 = {};
    v0[Symbol.search] = function () {
        return 42;
    };
    return ''.search(v0) === 42;
}
if (!f0())
    throw new Error('Test failed');
