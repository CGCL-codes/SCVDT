function f0() {
    return typeof String.prototype.includes === 'function' && 'foobar'.includes('oba');
}
if (!f0())
    throw new Error('Test failed');
