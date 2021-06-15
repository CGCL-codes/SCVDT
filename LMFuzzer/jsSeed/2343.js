function f0(value) {
    WScript.Echo(value);
}
var v0 = {}, v1 = {};
v0.x = 'A';
v0.y = 'B';
v1.y = 'C';
v1.x = 'D';
f0(v0.x);
f0(v0.y);
f0(v1.x);
f0(v1.y);
