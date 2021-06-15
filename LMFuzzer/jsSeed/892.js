function f0() {
    var v0;
    try {
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
