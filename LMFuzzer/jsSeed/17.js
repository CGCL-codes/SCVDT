if (Date.UTC.hasOwnProperty('length') !== true) {
    $ERROR('#1: The UTC has a "length" property');
}
if (Date.UTC.length !== 7) {
    $ERROR('#2: The "length" property of the UTC is 7');
}
