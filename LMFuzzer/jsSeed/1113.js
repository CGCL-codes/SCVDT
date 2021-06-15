var v0 = new Array(1);
var v1 = v0.splice(1, 2);
var v2 = {};
v2.length = 2;
v2.splice = Array.prototype.splice;
Object.prototype.splice = Array.prototype.splice;
WScript.Echo('ok');
