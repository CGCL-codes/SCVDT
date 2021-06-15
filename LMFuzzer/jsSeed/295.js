if ('abcd'.indexOf('abcdab', NaN) !== -1) {
    $ERROR('#1: "abcd".indexOf("abcdab",NaN)===-1. Actual: ' + 'abcd'.indexOf('abcdab', NaN));
}
