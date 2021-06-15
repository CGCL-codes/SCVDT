function f0() {
    var v0 = { bar: 456 };
    Reflect.deleteProperty(v0, 'bar');
    return !('bar' in v0);
}
if (!f0())
    throw new Error('Test failed');
