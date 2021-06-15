function f0() {
    return typeof Number.isSafeInteger === 'function';
}
if (!f0())
    throw new Error('Test failed');
