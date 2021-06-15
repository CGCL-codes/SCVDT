function f0() {
    var v0 = Symbol();
    try {
        new Symbol();
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
