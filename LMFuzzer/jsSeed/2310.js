function f0() {
    return function (...args) {
        try {
        } catch (e) {
            return true;
        }
    }();
}
if (!f0())
    throw new Error('Test failed');
