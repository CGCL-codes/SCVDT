import os

from common.config import RULE_DIR, LOG_DIR
from common.io import write_log
from common.models import Rule
from graph_process.database import add_rule, query_vuln_type, add_relation


def add_rule_to_graph():
    for cwe in os.listdir(RULE_DIR):
        for file in os.listdir(os.path.join(RULE_DIR, cwe)):
            # try:
            if file.endswith('.ql') and not file.endswith('Test.ql'):
                print('[+] add rule file: {0} to knowledge graph.'.format(cwe + '/' + file))
                f = open(os.path.join(RULE_DIR, cwe, file), 'r')
                flag = False
                description = str()
                for item in f.readlines():
                    if item.strip().startswith('* @description'):
                        flag = True
                        description += item.strip()[15:]
                    elif flag:
                        description += ' ' + item.strip()[1:].strip()
                    if item.strip().endswith('.'):
                        break
                rule = Rule()
                rule.setCWEID(cwe.replace('CWE-0', 'CWE-'))
                rule.setDescription(description)
                rule.setFile('{0}/{1}/{2}'.format('/root/work/Program/rules', cwe, file))
                # print(rule)
                rule_node = add_rule(rule)
                cwe_node = query_vuln_type(rule.cwe_id)
                if cwe_node is not None and len(cwe_node) > 0:
                    cwe_node = cwe_node[0]['a']
                    # print(cwe_node)
                    add_relation(cwe_node, 'has', rule_node)
                else:
                    log_file = r'{0}/rule-log.txt'.format(LOG_DIR)
                    write_log(log_file, '{0} does not exist in graph error.'.format(rule.cwe_id))
                print('successfully finished.')
            # except Exception as e:
            #     log_file = r'{0}/rule-log.txt'.format(LOG_DIR)
            #     write_log(log_file, '{0}->{1} to graph error.'.format(cwe, rule.rule_file))


if __name__ == '__main__':
    add_rule_to_graph()