function f0() {
    return typeof Number.isNaN === 'function';
}
if (!f0())
    throw new Error('Test failed');
