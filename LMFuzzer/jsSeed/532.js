function f0() {
    return typeof class {
    } === 'function';
}
if (!f0())
    throw new Error('Test failed');
