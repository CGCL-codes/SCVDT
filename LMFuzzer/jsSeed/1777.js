function f0() {
    var v0 = new Map();
    return v0.set(0, 0) === v0;
}
if (!f0())
    throw new Error('Test failed');
