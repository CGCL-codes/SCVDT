if (delete Math.E !== false) {
    $ERROR('#1: delete Math.E === false. Actual: ' + delete Math.E);
}
;
if (Math.E === undefined) {
    $ERROR('#2: delete Math.E; Math.E !== undefined');
}
;
