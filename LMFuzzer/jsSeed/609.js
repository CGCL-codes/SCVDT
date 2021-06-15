function f0(v1) {
    for (var v0 = 0; v0 < 1; ++v0) {
        v1[1] = 0;
        v1[0] = 0;
    }
}
f0([
    0,
    0
]);
var v1 = [];
f0(v1);
WScript.Echo('test0: ' + v1[1]);
