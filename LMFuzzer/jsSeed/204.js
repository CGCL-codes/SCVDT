function f0() {
    return arguments;
}
var v0 = f0(1);
var v1 = f0(1);
v0.__proto__ = v1;
delete v0[0];
v0[0];
