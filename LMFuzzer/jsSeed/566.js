function f0() {
    return arguments;
}
var v0 = f0();
v0.length = -100;
Array.prototype.slice.call(v0);
