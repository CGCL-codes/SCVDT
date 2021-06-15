function f0() {
    try {
        for (var v0 = 0 in {}) {
        }
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
