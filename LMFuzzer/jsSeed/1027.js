assert.throws(SyntaxError, function () {
    'use strict';
    eval('var public = 1;');
});
