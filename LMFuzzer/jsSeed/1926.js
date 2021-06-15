function f0() {
    var [a, b] = [
        ,
        ,
    ];
    return a === undefined && b === undefined;
}
if (!f0())
    throw new Error('Test failed');
