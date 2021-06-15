function f0() {
    return class foo {
    }.name === 'foo' && typeof class bar {
        static name() {
        }
    }.name === 'function';
}
if (!f0())
    throw new Error('Test failed');
