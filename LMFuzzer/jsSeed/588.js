if (/,\;/.source !== ',\\;') {
    $ERROR('#1: /,\\;/');
}
if (/ \ /.source !== ' \\ ') {
    $ERROR('#2: / \\ /');
}
