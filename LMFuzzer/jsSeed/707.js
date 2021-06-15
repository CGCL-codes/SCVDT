var v0 = /[]a/.test('\0a\0a');
;
if (v0) {
    $ERROR('#1: /[]a/.test("\\0a\\0a") === false');
}
