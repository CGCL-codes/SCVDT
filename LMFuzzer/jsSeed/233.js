function f0() {
    var v0 = new Set();
    return v0.add(0) === v0;
}
if (!f0())
    throw new Error('Test failed');
