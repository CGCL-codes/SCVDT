function f0(arg) {
    var v0 = String.fromCharCode(arg).charCodeAt();
    WScript.Echo(v0);
}
f0(0);
var v1 = 65532;
for (var v2 = 0; v2 < 10; v2++) {
    f0(v1);
    v1++;
}
