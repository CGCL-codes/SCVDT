function f0() {
    var v0 = {};
    v0[Symbol.replace] = function () {
        return 42;
    };
    return ''.replace(v0) === 42;
}
if (!f0())
    throw new Error('Test failed');
