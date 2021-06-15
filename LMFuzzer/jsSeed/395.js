var v0 = 0;
var v1;
v1 = function ([x] = []) {
    assert.sameValue(x, undefined);
    v0 = v0 + 1;
};
v1();
assert.sameValue(v0, 1, 'function invoked exactly once');
