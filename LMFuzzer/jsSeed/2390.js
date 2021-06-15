var v0 = Boolean(true);
v0.__defineSetter__('something', function () {
});
var v1 = Boolean(true);
v1.__defineGetter__('something else', function () {
});
WScript.Echo('Pass');
