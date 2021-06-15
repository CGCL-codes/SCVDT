if (true == 1 !== true) {
    $ERROR('#1: (true == 1) === true');
}
if (false == '0' !== true) {
    $ERROR('#2: (false == "0") === true');
}
