var v0 = /\be/.test('pilot\nsoviet robot\topenoffice');
if (v0) {
    $ERROR('#1: /\\be/.test("pilot\\nsoviet robot\\topenoffic\\u0065") === false');
}
