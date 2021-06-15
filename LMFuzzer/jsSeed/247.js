do {
    var v0 = 1;
    if (v0)
        break;
} while ({});
if (v0 !== 1) {
    $ERROR('#1: "{}" in do-while expression evaluates to true');
}
