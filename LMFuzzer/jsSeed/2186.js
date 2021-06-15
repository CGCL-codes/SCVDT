var v0 = 0;
var v1 = { x: 'obj' };
function f0() {
    with (v1) {
        return v0;
    }
}
if (!(f0() === 'obj')) {
    $ERROR('#1: Scope chain disturbed');
}
