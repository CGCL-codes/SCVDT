function f0() {
    return v0.C + v0.F;
}
var v0 = {
    D: 5,
    F: 2
};
Object.prototype.C = 10;
WScript.Echo(f0());
v0.B = 5;
WScript.Echo(f0());
WScript.Echo(f0());
v0.C = 99;
WScript.Echo(f0());
