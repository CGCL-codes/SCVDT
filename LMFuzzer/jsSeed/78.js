var v0 = 0;
for (var [x = 23] = [,]; v0 < 1;) {
    assert.sameValue(x, 23);
    v0 += 1;
}
assert.sameValue(v0, 1, 'Iteration occurred as expected');
