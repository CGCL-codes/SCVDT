var v0 = '//CHECK#1\n' + 'for (var x in this) {\n' + '  if ( x === \'Math\' ) {\n' + '    $ERROR("#1: \'Math\' have attribute DontEnum");\n' + '  }\n' + '}\n';
eval(v0);
