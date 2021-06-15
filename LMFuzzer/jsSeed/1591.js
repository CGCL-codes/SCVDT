assert.throws(SyntaxError, function () {
    eval('\'\nstr\ning\n\'');
});
