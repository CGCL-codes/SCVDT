function f0() {
    var v0 = 'foo';
    return {
        f() {
            return v0;
        }
    }.f() === 'foo';
}
if (!f0())
    throw new Error('Test failed');
