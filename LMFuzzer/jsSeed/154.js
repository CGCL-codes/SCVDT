if (new String('undefined').slice(v0, 3) !== 'und') {
    $ERROR('#1: var x; new String("undefined").slice(x,3) === "und". Actual: ' + new String('undefined').slice(v0, 3));
}
var v0;
