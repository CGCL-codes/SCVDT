function f0() {
    with (v0)
        var v0 = 0;
}
f0();
function f1() {
    eval('with (arguments) var arguments = 0;');
}
f1();
