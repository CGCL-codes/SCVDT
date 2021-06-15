function f0() {
    const v0 = 123;
    return v0 === 123;
}
if (!f0())
    throw new Error('Test failed');
