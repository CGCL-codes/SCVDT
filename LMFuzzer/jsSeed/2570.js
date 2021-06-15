var v0 = 0;
function f0() {
    function f1() {
        return v0;
    }
    ;
    return f1();
    var v0 = 1;
}
if (!(f0() === undefined)) {
    $ERROR('#1: Scope chain disturbed');
}
