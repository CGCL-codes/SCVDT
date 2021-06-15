function f0() {
    return Reflect.getPrototypeOf([]) === Array.prototype;
}
if (!f0())
    throw new Error('Test failed');
