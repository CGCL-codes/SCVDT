function f0() {
}
(function () {
    f0();
}());
function f1() {
    new f0() >> 0;
}
f1();
