var v0 = {};
Object.defineProperties(v0, { prop: { value: 1001 } });
for (var v1 in v0) {
    if (v0.hasOwnProperty(v1)) {
        assert.notSameValue(v1, 'prop', 'prop');
    }
}
