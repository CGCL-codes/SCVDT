function f0() {
    var v0 = () => 5;
    return !v0.hasOwnProperty('prototype');
}
if (!f0())
    throw new Error('Test failed');
