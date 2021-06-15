function f0() {
    var v0;
    function f1() {
        v0 = function () {
        };
    }
    for (var v1 in f1()) {
    }
    arguments[arguments.length - 1];
}
f0();
