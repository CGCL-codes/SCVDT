'use strict';
if (function () {
        return typeof this;
    }() !== 'undefined') {
    throw '\'this\' had incorrect value!';
}
