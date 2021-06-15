function f0() {
    var v0 = [], v1 = [];
    v1[Symbol.isConcatSpreadable] = false;
    v0 = v0.concat(v1);
    return v0[0] === v1;
}
if (!f0())
    throw new Error('Test failed');
