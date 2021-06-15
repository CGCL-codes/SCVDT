function f0() {
    new WeakMap();
    try {
        WeakMap();
        return false;
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
