function f0() {
    class C {
    }
    try {
        C();
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
