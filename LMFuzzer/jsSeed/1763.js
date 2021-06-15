for (x in function __func() {
        return { a: 1 };
    }()) {
    var v0 = x;
}
;
if (v0 !== 'a') {
    $ERROR('#2: function expession inside of for-in expression allowed');
}
