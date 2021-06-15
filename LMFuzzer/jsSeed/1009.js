if (+0 == -0 !== true) {
    $ERROR('#1: (+0 == -0) === true');
}
if (-0 == +0 !== true) {
    $ERROR('#2: (-0 == +0) === true');
}
