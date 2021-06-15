var v0;
v0 = /(?:)/i;
if (v0.ignoreCase !== true) {
    $ERROR('#1: var regexp = /(?:)/\\u0069; regexp.ignoreCase === true. Actual: ' + v0.ignoreCase);
}
