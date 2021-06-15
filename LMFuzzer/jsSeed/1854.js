function f0() {
    return typeof Number.MIN_SAFE_INTEGER === 'number';
}
if (!f0())
    throw new Error('Test failed');
