function f0() {
    var v0 = {};
    Reflect.setPrototypeOf(v0, Array.prototype);
    return v0 instanceof Array;
}
if (!f0())
    throw new Error('Test failed');
