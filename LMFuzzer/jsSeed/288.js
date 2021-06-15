function f0(o) {
    o.__defineSetter__('property', function () {
    });
}
f0(Object.prototype);
v0 = 0;
f0(this);
var v1 = Object.keys(this);
