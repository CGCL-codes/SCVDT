function f0() {
    var v0 = Object.assign({ a: true }, { b: true }, { c: true });
    return 'a' in v0 && 'b' in v0 && 'c' in v0;
}
if (!f0())
    throw new Error('Test failed');
