if (('' ? '' : '1') !== '1') {
    $ERROR('#1: ("" ? "" : "1") === "1"');
}
var v0 = new String('1');
if (('' ? '1' : v0) !== v0) {
    $ERROR('#2: (var y = new String("1"); ("" ? "1" : z) === z');
}
