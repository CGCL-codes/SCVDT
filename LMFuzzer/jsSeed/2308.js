function f0() {
    return typeof Math.acosh === 'function';
}
if (!f0())
    throw new Error('Test failed');
