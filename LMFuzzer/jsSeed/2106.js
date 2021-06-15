function f0(v1, i) {
    var v0 = v1.charCodeAt(i);
    WScript.Echo(v0);
}
var v1 = 'Hello';
f0(v1, 0);
f0(v1, 1);
f0(v1, -1);
f0(v1, 10);
f0(v1, 2.32);
f0(v1, Math.PI);
