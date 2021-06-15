

visualize_analysis = {}

def register_ana(name, analysis):
    global visualize_analysis
    visualize_analysis[name] = analysis


import heap_analysis
import call_analysis
import got_analysis
import leak_analysis
import shellcode_analysis