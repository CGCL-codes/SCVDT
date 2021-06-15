function f0() {
    var v0 = [5];
    for (var v1 of v0)
        return v1 === 5;
}
if (!f0())
    throw new Error('Test failed');
