function f0() {
    return new Date(NaN) + '' === 'Invalid Date';
}
if (!f0())
    throw new Error('Test failed');
