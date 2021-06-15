function f0() {
    eval('with (arguments) var arguments = 0;');
}
f0();
function f1() {
    eval('eval(\'with (arguments) var arguments = 0;\')');
}
f1();
