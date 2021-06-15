if (new String('undefined').substring(v0, 3) !== 'und') {
    $ERROR('#1: var x; new String("undefined").substring(x,3) === "und". Actual: ' + new String('undefined').substring(v0, 3));
}
var v0;
