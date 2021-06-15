if (String(+0) !== '0') {
    $ERROR('#1: String(+0) === "0". Actual: ' + String(+0));
}
if (String(-0) !== '0') {
    $ERROR('#2: String(-0) === "0". Actual: ' + String(-0));
}
