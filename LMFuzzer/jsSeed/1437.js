function f0(val, idx) {
    return val > 10 && arguments[2][idx] === val;
}
var v0 = [11].map(f0);
assert.sameValue(v0[0], true, 'testResult[0]');
