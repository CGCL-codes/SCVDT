if (function () {
        'use strict';
        return typeof this;
    }() !== 'undefined') {
    throw '\'this\' had incorrect value!';
}
