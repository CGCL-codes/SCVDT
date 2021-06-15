var v0 = {};
Object.defineProperty(v0, 'foo', {
    get: function () {
        return this;
    }
});
if (v0.foo !== v0) {
    throw '\'this\' had incorrect value!';
}
