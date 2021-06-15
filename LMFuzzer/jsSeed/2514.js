function f0() {
    return typeof Number.isInteger === 'function';
}
if (!f0())
    throw new Error('Test failed');
