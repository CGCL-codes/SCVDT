function f0() {
    var v0 = { 𐋀: 2 };
    return v0['\u102C0'] === 2;
}
if (!f0())
    throw new Error('Test failed');
