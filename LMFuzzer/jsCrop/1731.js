function f0(expected, actual, message = '') {
}
function f1(h = () => f2) {
    function f2() {
    }
    f0(f2, h());
}
f1();
