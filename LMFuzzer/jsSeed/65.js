function f0(o) {
    o.__proto__ = arguments;
    o.length = 123;
}
function f1() {
    f0(arguments);
}
f1();
