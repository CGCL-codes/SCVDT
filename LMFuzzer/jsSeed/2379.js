var v0;
v0 = /(?:)/g;
if (v0.global !== true) {
    $ERROR('#1: var regexp = /(?:)/\\u0067; regexp.global === true. Actual: ' + v0.global);
}
