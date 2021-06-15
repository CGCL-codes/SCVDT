function f0() {
    var v0 = {};
    var v1 = Symbol();
    var v2 = {};
    v0[v1] = v2;
    return v0[v1] === v2;
}
if (!f0())
    throw new Error('Test failed');
