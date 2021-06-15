var v0 = 0;
function f0() {
    function f1() {
        return v0;
    }
    ;
    var v0 = 1;
    return f1();
}
if (!(f0() === 1)) {
    $ERROR('#1: Scope chain disturbed');
}
