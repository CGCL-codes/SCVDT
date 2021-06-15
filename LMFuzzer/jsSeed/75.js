function f0() {
    if (delete arguments) {
        $ERROR('#1: Function parameters have attribute {DontDelete}' + arguments);
    }
    return arguments;
}
f0();
