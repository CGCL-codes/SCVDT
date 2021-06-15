var v0 = 'caps';
var v1 = String(v0);
if (v1 !== v0) {
    $ERROR('#1: __obj__str = "caps"; __str = String(__obj__str); __str === __obj__str. Actual: __str ===' + v1);
}
