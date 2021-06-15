if (!Number.hasOwnProperty('length')) {
    $ERROR('#1: Number constructor has length property');
}
if (Number.length !== 1) {
    $ERROR('#2: Number constructor length property value is 1');
}
