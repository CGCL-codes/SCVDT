function f0() {
    return Object.getPrototypeOf('a').constructor === String;
}
if (!f0())
    throw new Error('Test failed');
