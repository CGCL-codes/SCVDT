function f0() {
    return new Function('a', '...b', 'return b instanceof Array && a+b === \'foobar,baz\';')('foo', 'bar', 'baz');
}
if (!f0())
    throw new Error('Test failed');
