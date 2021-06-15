function f0() {
    var v0 = Symbol();
    var v1 = Object(v0);
    return typeof v1 === 'object' && v1 == v0 && v1 !== v0 && v1.valueOf() === v0;
}
if (!f0())
    throw new Error('Test failed');
