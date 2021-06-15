do {
    var v0 = 1;
    break;
} while (function __func() {
    return 0;
}());
if (v0 !== 1) {
    $ERROR('#2: function expession inside of do-while expression is allowed');
}
