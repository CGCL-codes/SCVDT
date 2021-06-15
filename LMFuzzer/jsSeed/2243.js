function f0() {
    return new RegExp(/./im, 'g').global === true;
}
if (!f0())
    throw new Error('Test failed');
