function f0() {
}
f0.prototype.bar = function () {
    print('yes hello');
    return 5;
};
var v0 = new f0();
function f1(v0) {
    for (var v1 = 0; v1 < 41; v1++);
    v0.bar();
}
f1(v0);
