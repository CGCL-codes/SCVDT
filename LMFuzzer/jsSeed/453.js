while (function __func() {
        return 1;
    }()) {
    var v0 = 1;
    break;
}
;
if (v0 !== 1) {
    $ERROR('#2: function expression inside of while expression is allowed');
}
