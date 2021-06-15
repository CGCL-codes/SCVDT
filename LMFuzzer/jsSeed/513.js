var v0 = {};
var v1 = function () {
    return 'present';
};
Object.defineProperties(v0, { property: { get: v1 } });
assert.sameValue(v0.property, 'present', 'obj.property');
