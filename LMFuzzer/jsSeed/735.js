function f0() {
    return typeof String.prototype.endsWith === 'function' && 'foobar'.endsWith('bar');
}
if (!f0())
    throw new Error('Test failed');
