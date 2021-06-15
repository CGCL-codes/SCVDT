function f0() {
}
function f1() {
    f0.call(this);
}
var v0 = 30 * 1024 - 1;
var v1 = new f1();
for (var v2 = 0; v2 < v0; v2++) {
    v1.next = new function () {
    }();
    v1 = v1.next;
}
