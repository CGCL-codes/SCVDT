if (String('lego').concat(undefined) !== 'legoundefined') {
    $ERROR('#1: String("lego").concat(undefined) === "legoundefined". Actual: ' + String('lego').concat(undefined));
}
