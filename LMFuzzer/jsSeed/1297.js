if (!' ' !== false) {
    $ERROR('#1: !(" ") === false. Actual: ' + !' ');
}
if (!'Nonempty String' !== false) {
    $ERROR('#2: !("Nonempty String") === false. Actual: ' + !'Nonempty String');
}
