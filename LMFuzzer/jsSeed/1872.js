function f0() {
    new Proxy({}, {});
    try {
        Proxy({}, {});
        return false;
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
