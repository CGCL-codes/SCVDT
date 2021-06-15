# !pip install brewer2mpl
import numpy as np
# import pandas as pd
# from pandas.core.frame import DataFrame
# from io import BytesIO
# import base64
# import matplotlib
# matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import seaborn as sns
# import warnings; warnings.filterwarnings(action='once')
import mpld3


# %matplotlib inline
# # Version
# # print(mpl.__version__)  #> 3.0.0
# print(sns.__version__)  #> 0.9.0
def generate_warning_timepicture(lists = []):
    # df_raw = DataFrame(list)
    large = 22;
    med = 16;
    small = 12
    params = {'axes.titlesize': large,
              'legend.fontsize': med,
              'figure.figsize': (10, 5),
              'axes.labelsize': med,
              'axes.titlesize': med,
              'xtick.labelsize': small,
              'ytick.labelsize': med,
              'figure.titlesize': large}
    plt.rcParams.update(params)
    plt.style.use('seaborn-whitegrid')
    sns.set_style("white")

    lists = [[list[0], int(list[1])] for list in lists]
    lists.sort(key=lambda x : x[1])
    # print(lists)
    y = np.array([list[0] for list in lists], dtype=str)
    x = np.array([list[1] for list in lists], dtype=str)
    y_label = np.unique(y)
    x_label = np.unique(x)


    fig = plt.figure(figsize=(14,5), dpi=70)
    fig.subplots_adjust(left=0.18, right=0.99)
    ax = plt.subplot()
    ax.scatter(x, y, s=75, color='firebrick', alpha=0.7)
    ax.grid(axis='y', color='gray', alpha=0.7, linewidth=1, linestyle='dashdot', which='major')
    ax.set_yticks(y_label)
    ax.set_yticklabels(y_label, fontdict={'horizontalalignment': 'right', 'verticalalignment': 'bottom'})
    # ax.yaxis.set_ticks_position('left')
    # ax.spines['left'].set_position(('data', 1))
    ax.set_xticks(x_label)
    ax.set_xticklabels(x_label, fontdict={'horizontalalignment': 'right'})


    ax.set_xlabel('state timestamp')
    # plt.show()

    html = mpld3.fig_to_html(fig)
    # sio = BytesIO()
    # fig.savefig(sio)
    # encoded = base64.b64encode(sio.getvalue()).decode('utf-8')
    # html = 'Some html head' + '<img src=\'data:image/png;base64,{}\'>'.format(encoded) + 'Some more html'
    # plt.savefig(sio, format='svg', bbox_inches='tight', pad_inches=0.0)
    # data = base64.encodebytes(sio.getvalue()).decode()
    # src = 'data:image/svg;base64,{%s}' % str(data)
    plt.close()
    # print(src)
    # print(html)
    # return '/tmp/timepic'
    with open("/tmp/timepic.html", "w") as f:
        f.write(html)
    f.close()
    return "/tmp/timepic.html"