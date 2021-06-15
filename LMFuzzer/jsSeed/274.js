function f0() {
    function f1() {
    }
    ;
    return f1.name === 'foo' && function () {
    }.name === '';
}
if (!f0())
    throw new Error('Test failed');
