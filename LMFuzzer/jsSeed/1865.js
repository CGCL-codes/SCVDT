var v0 = [0];
v0[1] = 1;
v0[2] = 2;
Array.prototype[3] = 3;
v0[6] = 4;
function f0() {
    return v0.pop();
}
var v1 = v0.length;
for (v2 = 0; v2 <= v1; v2++) {
    WScript.Echo(f0());
}
