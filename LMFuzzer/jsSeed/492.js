function f0() {
    return Object.setPrototypeOf({}, Array.prototype) instanceof Array;
}
if (!f0())
    throw new Error('Test failed');
