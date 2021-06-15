function f0() {
    try {
        eval('({ __proto__ : [], __proto__: {} })');
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
