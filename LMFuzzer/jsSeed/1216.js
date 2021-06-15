v0 = RegExp('', '');
v1 = 'a';
v0.exec(v1);
v0['@'] = 42;
v0.exec(v1);
