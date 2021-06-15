Object.defineProperty(Object.prototype, 'x', {
    set: function () {
    }
});
var v0 = {};
for (var v1 = 0; v1 < 100; ++v1) {
    v0.x = 1;
    delete v0.x;
}
