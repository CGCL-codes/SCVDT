function f0() {
    const v0 = 1;
    try {
        Function('const foo = 1; foo = 2;')();
    } catch (e) {
        return true;
    }
}
if (!f0())
    throw new Error('Test failed');
