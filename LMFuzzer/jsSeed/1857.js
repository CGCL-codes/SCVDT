if (eval('"BJ"').toLocaleLowerCase() !== 'bj') {
    $ERROR('#1: eval("\\"BJ\\"").toLocaleLowerCase() === "bj". Actual: ' + eval('"BJ"').toLocaleLowerCase());
}
