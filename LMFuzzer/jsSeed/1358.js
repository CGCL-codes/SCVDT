outer:
    for (var v0 = 0; v0 < 10; v0++)
        for (var v1 in { x: 1 })
            if (v1 > 'q')
                continue outer;
