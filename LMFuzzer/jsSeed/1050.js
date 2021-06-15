if (eval('switch(1){}') !== undefined) {
    $ERROR('#1: eval("switch(1){}") === undefined. Actual: ' + eval('switch(1){}'));
}
