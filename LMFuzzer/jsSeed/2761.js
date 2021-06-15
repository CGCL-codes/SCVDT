function f0() {
    var v0 = {};
    Reflect.preventExtensions(v0);
    return !Object.isExtensible(v0);
}
if (!f0())
    throw new Error('Test failed');
