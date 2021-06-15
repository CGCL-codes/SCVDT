function f0() {
    eval('var { [arguments] : y } = {};');
}
f0();
