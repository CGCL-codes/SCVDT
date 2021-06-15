function f0() {
    return typeof Number.EPSILON === 'number';
}
if (!f0())
    throw new Error('Test failed');
