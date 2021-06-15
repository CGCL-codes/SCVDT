function f0() {
    return Reflect.isExtensible({}) && !Reflect.isExtensible(Object.preventExtensions({}));
}
if (!f0())
    throw new Error('Test failed');
