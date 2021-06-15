function f0() {
    var v0 = 7, v1 = 8, v2 = {
            a,
            b
        };
    return v2.a === 7 && v2.b === 8;
}
if (!f0())
    throw new Error('Test failed');
