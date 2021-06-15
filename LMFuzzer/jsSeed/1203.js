var v0 = new Object();
function f0(k, v) {
    return v;
}
for (var v1 = 0; v1 < 1290; v1++) {
    v0[v1 + 10] = 0;
}
WScript.Echo(JSON.stringify(v0, f0).substring(0, 20));
