function f0() {
    var v0 = {};
    v0[Symbol.match] = function () {
        return 42;
    };
    return ''.match(v0) === 42;
}
if (!f0())
    throw new Error('Test failed');
