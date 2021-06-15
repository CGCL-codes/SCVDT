from jinja2 import Environment, FileSystemLoader
from .log_parse import *
from .env_info import *
from .timestamp_picture import *
import time

def generate_report(binary_path, map_path, template_name="template.html", report_name = "report.html", \
                    analysis_path = ""):
    '''
    the report will be generated in current directory
    :param binary_path:
    :param template_name:
    :param report_name:
    :param analysis_path:
    :return:
    '''

    path = __file__[:__file__.rfind("/")+1]

    checksec_info = get_checksec_info(binary_path).replace("\n", "<br/>")
    os_info = get_os_info()
    memory_info = get_map_info(map_path).replace("\n", "<br/>").replace(" ", "&nbsp;").replace("\t", "&emsp;"*2)

    report = report_log(analysis_path)

    got_output = report.get_got_output()
    leak_output = report.get_leak_output()
    call_output = report.get_call_output()
    heap_output = report.get_heap_output()
    shell_output = report.get_shell_output()
    heap_image_path = report.get_heap_graph()

    syscall_warning_image_path = report.get_syscalls_warning_picture()

    warning_image_path = generate_warning_timepicture(report.get_warning_statestamp())

    def generate_html(got_output=[], \
                      heap_image_path="/tmp/HeapChange.svg", \
                      warning_image_path="/tmp/timepic.html", \
                      syscall_warning_image_path="/tmp/syscallWarning.svg", \
                      heap_output=[] , leak_output=[], call_output=[], shell_output=[]):
        '''
        :param got_table:
        :param image_path:
        :param leak_table:
        :return:
        '''
        path = __file__[:__file__.rfind("/")]
        work_path = os.getcwd()
        os.system("cp -rf %s/html %s"%(path, work_path))
        html_path = os.getcwd()+"/html/"
        if os.access(heap_image_path,os.F_OK):
            os.system("cp -f %s %s" % (heap_image_path, html_path))
            heap_image_path = "./HeapChange.svg"
        else:
            print("Heap change image not found!")
            heap_image_path = ""

        if os.access(warning_image_path,os.F_OK):
            os.system("cp -f %s %s" % (warning_image_path, html_path))
            warning_image_path = "./timepic.html"
        else:
            print("Timestamp image not found!")
            warning_image_path = ""

        if os.access(syscall_warning_image_path, os.F_OK):
            os.system("cp -f %s %s" % (syscall_warning_image_path, html_path))
            heap_image_path = "./syscallWarning.svg"
        else:
            print("Syscalls image not found!")
            syscall_warning_image_path = ""

        env = Environment(loader=FileSystemLoader(html_path))
        template = env.get_template(template_name)

        report_time = time.strftime('%Y.%m.%d', time.localtime(time.time()))
        with open(os.path.join(html_path, report_name), 'w+') as fout:
            html_content = template.render(osinfo=os_info, \
                                           checksecinfo=checksec_info, \
                                           memoryinfo=memory_info, \
                                           reporttime=report_time, \
                                           syscallimage=syscall_warning_image_path,\
                                           gotoutput=got_output, \
                                           heapimage=heap_image_path, \
                                           warning_image=warning_image_path, \
                                           leakoutput=leak_output, \
                                           heapoutput=heap_output, \
                                           calloutput=call_output, \
                                           shelloutput=shell_output)
            fout.write(html_content)
            print("Report generated at %s/report.html" % html_path)
        fout.close()

    generate_html(got_output, \
                  heap_image_path, \
                  warning_image_path, \
                  syscall_warning_image_path, \
                  heap_output, leak_output, call_output, shell_output)

if __name__ == '__main__':
    generate_report("../../test/packed_heap_sample/easyheap", report_name="report_new.html", \
                    analysis_path="../../test/packed_heap_sample/analysis.log")