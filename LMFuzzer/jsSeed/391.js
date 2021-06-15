function f0() {
    var v0, v1, v2 = {
            a: 1,
            b: 2
        };
    return ({a, b} = v2) === v2;
}
if (!f0())
    throw new Error('Test failed');
