var v0 = /["'][^"']*["']/.test('alice cries out: don\'t');
if (v0) {
    $ERROR('#1: /["\'][^"\']*["\']/.test(\'alice cries out: don\'t\') === false');
}
