load("fcfbc86708bc3a4062c2091a062e13b6.js");
load("faa81dc98fc13338aca921d45eebae79.js");
/// Copyright (c) 2012 Ecma International.  All rights reserved. 
/// Ecma International makes this code available under the terms and conditions set
/// forth on http://hg.ecmascript.org/tests/test262/raw-file/tip/LICENSE (the 
/// "Use Terms").   Any redistribution of this code must retain the above 
/// copyright and this notice and otherwise comply with the Use Terms.
/**
 * @path ch11/11.8/11.8.2/11.8.2-3.js
 * @description 11.8.2 Greater-than Operator - Partial left to right order enforced when using Greater-than operator: toString > valueOf
 */


function testcase() {
        var accessed = false;
        var obj1 = {
            toString: function () {
                accessed = true;
                return 3;
            }
        };
        var obj2 = {
            valueOf: function () {
                if (accessed === true) {
                    return 4;
                } else {
                    return 2;
                }
            }
        };
        return !(obj1 > obj2);
    }
runTestCase(testcase);
