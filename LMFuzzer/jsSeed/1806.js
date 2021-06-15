var v0 = 'FAIL';
Date.prototype.valueOf = function () {
    v0 = 'PASS';
    return ' ';
};
var v1 = new Date(2010, 11, 31, 0, 0, 0, 0);
var v2 = v1.toJSON();
WScript.Echo(v0);
