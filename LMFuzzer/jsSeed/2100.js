function f0() {
    var v0 = [
        ,
        ,
    ];
    var v1 = 0;
    for (var v2 of v0)
        v1 += v2 === undefined;
    return v1 === 2;
}
if (!f0())
    throw new Error('Test failed');
