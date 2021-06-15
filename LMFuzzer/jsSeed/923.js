if (/(?:)/ instanceof RegExp !== true) {
    $ERROR('#1: (/(?:)/ instanceof RegExp) === true. Actual: ' + (/(?:)/ instanceof RegExp));
}
