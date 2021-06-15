function f0() {
    var v0;
    try {
        eval('var v\\u0061r');
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
