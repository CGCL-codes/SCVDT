String.prototype.toString = function () {
    return 'PASS';
};
var v0 = new String('FAIL');
WScript.Echo(v0.substr(0, 4));
