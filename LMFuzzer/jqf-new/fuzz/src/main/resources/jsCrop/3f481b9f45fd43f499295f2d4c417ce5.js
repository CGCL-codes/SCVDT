function f0() {
    WScript.Echo(v0);
}
var v0;
v0 = 0;
v0 = 1;
WScript.Echo(v0);
v0 = 0;
f0();
v0 = 1;
WScript.Echo(v0);
v0 = 0;
var v1 = this;
var v2 = v1.i;
v1.i = -1;
v0 = 1;
WScript.Echo(v0);