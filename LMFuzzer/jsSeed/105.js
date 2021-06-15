var v0 = 0;
function f0() {
    return 3;
}
for (var v1 = 0; v1 < 10; v1++) {
    v0 += f0();
}
WScript.Echo(v0);
