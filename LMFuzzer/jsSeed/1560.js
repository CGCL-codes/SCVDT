function f0() {
    var v0 = eval;
}
f0();
var v1 = function (v0) {
    v0.apply(this);
};
function f1() {
    WScript.Echo('pass');
}
v1(f1);
