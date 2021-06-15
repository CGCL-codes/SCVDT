var v0 = new Function('"use strict";\nreturn typeof this;');
if (v0() !== 'undefined') {
    throw '\'this\' had incorrect value!';
}
