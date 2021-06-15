WScript.Echo('Basic string concatenation, II.');
function f0(x, y) {
    return x + '.' + y;
}
var v0 = '-';
for (var v1 = 0; v1 < 10; ++v1) {
    v0 = f0(v1, f0(v0, v1));
}
WScript.Echo(v0);
