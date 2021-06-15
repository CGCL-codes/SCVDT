if (delete x !== true) {
    $ERROR('#1: delete (x) === true');
}
if (typeof x !== 'undefined') {
    $ERROR('#2: typeof (x) === "undefined". Actual: ' + typeof x);
}
