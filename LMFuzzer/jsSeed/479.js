var v0;
for (v0 in function __func() {
        return { a: 1 };
    }()) {
    var v1 = v0;
}
;
if (v1 !== 'a') {
    $ERROR('#2: function expession inside of for-in expression allowed');
}
