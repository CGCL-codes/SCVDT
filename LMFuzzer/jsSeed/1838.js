var v0 = {};
v0.x = 1;
v0.y = 1.5;
var v1 = {};
v1.x = 1.5;
v1.__defineSetter__('y', function (v) {
});
v0.y;
