if (eval('"bj"').toLocaleUpperCase() !== 'BJ') {
    $ERROR('#1: eval("\\"bj\\"").toLocaleUpperCase() === "BJ". Actual: ' + eval('"bj"').toLocaleUpperCase());
}
