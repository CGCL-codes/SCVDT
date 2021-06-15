var v0 = {};
var v1 = 2;
Object.defineProperty(v0, 'foo', {
    set: function (stuff) {
        v1 = this;
    }
});
v0.foo = 3;
if (v1 !== v0) {
    throw '\'this\' had incorrect value!';
}
