function f0() {
    new Set();
    try {
        Set();
        return false;
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
