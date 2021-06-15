function f0(v) {
    WScript.Echo(v + '');
}
var v0 = function () {
};
f0('Initial  : ' + v0.hasOwnProperty('prototype'));
delete v0.prototype;
f0('Deletion : ' + v0.hasOwnProperty('prototype'));
