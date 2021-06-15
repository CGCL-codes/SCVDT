function f0() {
    var v0 = {};
    v0.__proto__ = Array.prototype;
    return v0 instanceof Array;
}
if (!f0())
    throw new Error('Test failed');
