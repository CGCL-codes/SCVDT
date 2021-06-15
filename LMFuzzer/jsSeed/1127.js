try {
    v0 = v0;
} catch (e) {
    $ERROR('#1: Variable declaration inside "for" loop is admitted');
}
;
for (;;) {
    break;
    var v0;
}
