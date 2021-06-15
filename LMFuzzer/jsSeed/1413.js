function f0(a) {
    f1(a, ' World');
}
f0('Hello');
function f1(a, b) {
    arguments.callee.caller.arguments[0] += b;
    WScript.Echo(a, b);
}
