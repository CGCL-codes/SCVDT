if (false + '' !== 'false') {
    $ERROR('#1: false + "" === "false". Actual: ' + (false + ''));
}
if (true + '' !== 'true') {
    $ERROR('#2: true + "" === "true". Actual: ' + (true + ''));
}
