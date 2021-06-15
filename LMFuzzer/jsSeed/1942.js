function f0() {
}
var v0 = {};
v0.gf = function* () {
    yield 0;
};
if (v0.gf().next().value === 0) {
    WScript.Echo('passed');
} else {
    WScript.Echo('failed');
}
