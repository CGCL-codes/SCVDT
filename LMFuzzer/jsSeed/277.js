function f0() {
    return typeof Object.is === 'function' && Object.is(NaN, NaN) && !Object.is(-0, 0);
}
if (!f0())
    throw new Error('Test failed');
