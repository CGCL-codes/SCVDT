var v0 = new Array(10);
var v1 = v0.splice(2147483648, 2);
var v2 = {};
v2.splice = Array.prototype.splice;
Object.prototype.splice = Array.prototype.splice;
WScript.Echo('ok');
