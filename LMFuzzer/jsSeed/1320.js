var v0 = [];
assert.throws(RangeError, function () {
    Object.defineProperties(v0, { length: { value: NaN } });
});
assert.sameValue(v0.length, 0, 'arr.length');
