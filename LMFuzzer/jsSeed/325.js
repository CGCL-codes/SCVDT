var v0 = 0;
function f0(x, y) {
    return x < y;
}
var v1 = 0;
do {
    v0 += v1;
    ++v1;
} while (f0(v1, 100) && f0(v0, 5000));
WScript.Echo(v0);
