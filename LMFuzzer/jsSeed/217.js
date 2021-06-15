if (eval('"bj"').toUpperCase() !== 'BJ') {
    $ERROR('#1: eval("\\"bj\\"").toUpperCase() === "BJ". Actual: ' + eval('"bj"').toUpperCase());
}
