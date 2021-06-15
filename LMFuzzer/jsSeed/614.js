var v0 = 1, v1 = 2;
function f0() {
    return;
    v0 + v1;
}
var v2 = f0();
if (v2 !== undefined)
    $ERROR('#1: Automatic semicolon insertion not work with return');
