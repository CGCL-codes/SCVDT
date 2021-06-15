if (('' || '1') !== '1') {
    $ERROR('#1: ("" || "1") === "1"');
}
var v0 = new String('1');
if (('' || v0) !== v0) {
    $ERROR('#2: (var y = new String("1"); "" || y) === y');
}
