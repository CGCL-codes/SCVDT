if (!Object.hasOwnProperty('length')) {
    $ERROR('#1: The Object constructor has the property "length"');
}
if (Object.length !== 1) {
    $ERROR('#2: Object.length property value should be 1');
}
