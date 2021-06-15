if (-false !== 0) {
    $ERROR('#1: -false === 0. Actual: ' + -false);
}
if (-new Boolean(true) !== -1) {
    $ERROR('#2: -new Boolean(true) === -1. Actual: ' + -new Boolean(true));
}
