let v0 = 2;
let v1 = 1;
function f0() {
    return 3;
}
function f1() {
    var v2 = f1;
    if (v1 == 1)
        WScript.Echo(v2.options);
}
f1.options = 'Pass';
f1();
