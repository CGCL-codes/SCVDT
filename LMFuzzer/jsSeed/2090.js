var v0 = {};
var v1 = new Proxy(v0, { defineProperty: {} });
assert.throws(TypeError, function () {
    Object.defineProperty(v1, 'foo', { value: 1 });
});
