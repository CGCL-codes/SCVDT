function f0() {
    return function (foo, ...args) {
        return args instanceof Array && args + '' === 'bar,baz';
    }('foo', 'bar', 'baz');
}
if (!f0())
    throw new Error('Test failed');
