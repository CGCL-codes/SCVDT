if ((0 ? 0 : 1) !== 1) {
    $ERROR('#1: (0 ? 0 : 1) === 1');
}
var v0 = new Number(1);
if ((0 ? 1 : v0) !== v0) {
    $ERROR('#2: (var y = new Number(1); (0 ? 1 : z) === z');
}
