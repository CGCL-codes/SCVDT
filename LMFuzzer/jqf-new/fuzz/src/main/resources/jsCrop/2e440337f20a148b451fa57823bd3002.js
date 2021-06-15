var v0 = {
    valueOf: function () {
        return '%5E';
    }
};
if (decodeURI(v0) !== '[object Object]') {
    $ERROR('#1: var object = {valueOf: function() {return "%5E"}}; decodeURI(object) === [object Object]. Actual: ' + decodeURI(v0));
}
var v0 = {
    valueOf: function () {
        return '';
    },
    toString: function () {
        return '%5E';
    }
};
if (decodeURI(v0) !== '^') {
    $ERROR('#2: var object = {valueOf: function() {return ""}, toString: function() {return "%5E"}}; decodeURI(object) === "^". Actual: ' + decodeURI(v0));
}
var v0 = {
    valueOf: function () {
        return '%5E';
    },
    toString: function () {
        return {};
    }
};
if (decodeURI(v0) !== '^') {
    $ERROR('#3: var object = {valueOf: function() {return "%5E"}, toString: function() {return {}}}; decodeURI(object) === "^". Actual: ' + decodeURI(v0));
}
try {
    var v0 = {
        valueOf: function () {
            throw 'error';
        },
        toString: function () {
            return '%5E';
        }
    };
    if (decodeURI(v0) !== '^') {
        $ERROR('#4.1: var object = {valueOf: function() {throw "error"}, toString: function() {return "%5E"}}; decodeURI(object) === "^". Actual: ' + decodeURI(v0));
    }
} catch (e) {
    if (e === 'error') {
        $ERROR('#4.2: var object = {valueOf: function() {throw "error"}, toString: function() {return "%5E"}}; decodeURI(object) not throw "error"');
    } else {
        $ERROR('#4.3: var object = {valueOf: function() {throw "error"}, toString: function() {return "%5E"}}; decodeURI(object) not throw Error. Actual: ' + e);
    }
}
var v0 = {
    toString: function () {
        return '%5E';
    }
};
if (decodeURI(v0) !== '^') {
    $ERROR('#5: var object = {toString: function() {return "%5E"}}; decodeURI(object) === "^". Actual: ' + decodeURI(v0));
}
var v0 = {
    valueOf: function () {
        return {};
    },
    toString: function () {
        return '%5E';
    }
};
if (decodeURI(v0) !== '^') {
    $ERROR('#6: var object = {valueOf: function() {return {}}, toString: function() {return "%5E"}}; decodeURI(object) === "^". Actual: ' + decodeURI(v0));
}
try {
    var v0 = {
        valueOf: function () {
            return '%5E';
        },
        toString: function () {
            throw 'error';
        }
    };
    decodeURI(v0);
    $ERROR('#7.1: var object = {valueOf: function() {return "%5E"}, toString: function() {throw "error"}}; decodeURI(object) throw "error". Actual: ' + decodeURI(v0));
} catch (e) {
    if (e !== 'error') {
        $ERROR('#7.2: var object = {valueOf: function() {return "%5E"}, toString: function() {throw "error"}}; decodeURI(object) throw "error". Actual: ' + e);
    }
}
try {
    var v0 = {
        valueOf: function () {
            return {};
        },
        toString: function () {
            return {};
        }
    };
    decodeURI(v0);
    $ERROR('#8.1: var object = {valueOf: function() {return {}}, toString: function() {return {}}}; decodeURI(object) throw TypeError. Actual: ' + decodeURI(v0));
} catch (e) {
    if (e instanceof TypeError !== true) {
        $ERROR('#8.2: var object = {valueOf: function() {return {}}, toString: function() {return {}}}; decodeURI(object) throw TypeError. Actual: ' + e);
    }
}