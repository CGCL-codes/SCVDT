var v0 = this;
function f0() {
    WScript.Echo(eval('"use strict";\ntypeof this'));
}
function f1() {
    WScript.Echo(eval('"use strict";\n this') === v0);
}
f0();
f1();
