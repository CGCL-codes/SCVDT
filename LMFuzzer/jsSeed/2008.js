if ('$$abcdabcd'.indexOf('ab', NaN) !== 2) {
    $ERROR('#1: "$$abcdabcd".indexOf("ab",NaN)===2. Actual: ' + '$$abcdabcd'.indexOf('ab', NaN));
}
