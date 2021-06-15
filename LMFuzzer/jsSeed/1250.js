function f0() {
    var v0 = {};
    v0[Symbol.split] = function () {
        return 42;
    };
    return ''.split(v0) === 42;
}
if (!f0())
    throw new Error('Test failed');
