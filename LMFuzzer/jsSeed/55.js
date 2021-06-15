function f0() {
    return typeof Number.isFinite === 'function';
}
if (!f0())
    throw new Error('Test failed');
