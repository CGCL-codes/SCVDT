if (String('undefined').search(undefined) !== 0) {
    $ERROR('#1: String("undefined").search(undefined) === 0. Actual: ' + String('undefined').search(undefined));
}
