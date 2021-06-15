function f0(i) {
    print(i);
}
function f1() {
    f0.apply({}, arguments);
}
function f2() {
    f1.apply({}, arguments);
}
function f3(a) {
    f2(a);
}
f3(1);
f3(1);
f3('');
f3('');
