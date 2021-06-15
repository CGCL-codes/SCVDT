function f0() {
    new Map();
    try {
        Map();
        return false;
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
