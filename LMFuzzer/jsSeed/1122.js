function f0() {
    new WeakSet();
    try {
        WeakSet();
        return false;
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
