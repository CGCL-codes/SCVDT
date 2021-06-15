var v0 = /[xyz]*1/.test('a0.b2.c3');
if (v0) {
    $ERROR('#1: /[xyz]*1/.test(\'a0.b2.c3\') === false');
}
