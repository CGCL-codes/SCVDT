function f0() {
    var v0 = function () {
    };
    return new v0().__proto__ === v0.prototype;
}
if (!f0())
    throw new Error('Test failed');
