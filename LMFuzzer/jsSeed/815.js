var v0, v1, v2;
var v3;
var v4 = [
    1,
    2,
    3
];
v3 = [v0, v1, v2] = v4;
assert.sameValue(v0, 1);
assert.sameValue(v1, 2);
assert.sameValue(v2, 3);
assert.sameValue(v3, v4);
