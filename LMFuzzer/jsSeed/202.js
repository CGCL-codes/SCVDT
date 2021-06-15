function f0() {
    return typeof String.prototype.startsWith === 'function' && 'foobar'.startsWith('foo');
}
if (!f0())
    throw new Error('Test failed');
