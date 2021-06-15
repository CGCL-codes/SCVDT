if (!Boolean.hasOwnProperty('length')) {
    $ERROR('#1: Boolean constructor has length property');
}
if (Boolean.length !== 1) {
    $ERROR('#2: Boolean constructor length property value is 1');
}
