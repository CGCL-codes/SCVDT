function f0() {
    var v0 = Array(...[
        ,
        ,
    ]);
    return '0' in v0 && '1' in v0 && '' + v0[0] + v0[1] === 'undefinedundefined';
}
if (!f0())
    throw new Error('Test failed');
