if (Date.parse.hasOwnProperty('length') !== true) {
    $ERROR('#1: The parse has a "length" property');
}
if (Date.parse.length !== 1) {
    $ERROR('#2: The "length" property of the parse is 1');
}
