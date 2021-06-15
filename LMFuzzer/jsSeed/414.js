function f0(arguments) {
    return arguments;
}
;
if (f0(42) !== 42) {
    $ERROR('#1: "arguments" variable overrides ActivationObject.arguments');
}
