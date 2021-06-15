if (+0 != -0 !== false) {
    $ERROR('#1: (+0 != -0) === false');
}
if (-0 != +0 !== false) {
    $ERROR('#2: (-0 != +0) === false');
}
