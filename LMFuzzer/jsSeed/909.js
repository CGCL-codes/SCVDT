var v0 = new Array(1, 2, 3, 4, 5, 6);
WScript.Echo(v0);
var v1 = Array.apply(this, v0);
WScript.Echo(v1);
