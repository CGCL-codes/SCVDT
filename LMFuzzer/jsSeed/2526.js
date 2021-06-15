function f0() {
    let v0 = 123;
    return v0 === 123;
}
if (!f0())
    throw new Error('Test failed');
