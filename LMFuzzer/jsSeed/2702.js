if (Number.prototype != 0) {
    $ERROR('#2: Number.prototype == +0');
} else if (1 / Number.prototype != Number.POSITIVE_INFINITY) {
    $ERROR('#2: Number.prototype == +0');
}
