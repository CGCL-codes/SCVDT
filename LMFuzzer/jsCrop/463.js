function f0() {
    function f1() {
    }
    this.d = function () {
        f1;
    };
}
(function () {
    var v0, v1;
    v0 = new f0();
    v2 = function () {
        v1 * 1;
    }();
}());
