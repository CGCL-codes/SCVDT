if (String('undefined').lastIndexOf(undefined) !== 0) {
    $ERROR('#1: String("undefined").lastIndexOf(undefined) === 0. Actual: ' + String('undefined').lastIndexOf(undefined));
}
