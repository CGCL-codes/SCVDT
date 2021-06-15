function f0(v0) {
    return 2 * v0;
}
var v0 = 1, v1 = 2, v2 = 4, v3 = 5;
v0 = v1 + f0(v2 + v3);
if (v0 !== 20)
    $ERROR('#1: Automatic semicolon insertion work wrong');
