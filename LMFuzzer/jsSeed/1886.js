function f0() {
    try {
        eval('for (var i = 0 in {}) {}');
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
