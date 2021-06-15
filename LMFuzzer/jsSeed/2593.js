var v0;
v0 = /(?:)/m;
if (v0.multiline !== true) {
    $ERROR('#1: var regexp = /(?:)/\\u006D; regexp.multiline === true. Actual: ' + v0.multiline);
}
