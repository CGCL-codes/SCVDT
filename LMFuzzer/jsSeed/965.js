function f0() {
    return typeof Number.MAX_SAFE_INTEGER === 'number';
}
if (!f0())
    throw new Error('Test failed');
