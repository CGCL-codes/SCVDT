function f0() {
    class C {
    }
    return typeof C === 'function';
}
if (!f0())
    throw new Error('Test failed');
