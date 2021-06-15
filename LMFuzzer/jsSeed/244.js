if (!Date.hasOwnProperty('length')) {
    $ERROR('#1: Date constructor has length property');
}
if (Date.length !== 7) {
    $ERROR('#2: Date constructor length property value should be 7');
}
