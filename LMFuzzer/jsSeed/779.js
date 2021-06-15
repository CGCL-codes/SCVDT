function f0() {
    return function foo() {
    }.name === 'foo' && function () {
    }.name === '';
}
if (!f0())
    throw new Error('Test failed');
