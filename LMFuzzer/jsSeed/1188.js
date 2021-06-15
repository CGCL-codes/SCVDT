function f0(v) {
    WScript.Echo(v);
}
Object.prototype.toString = function () {
    return 'toString() Overwritten';
};
var v0 = new Object();
f0(v0);
