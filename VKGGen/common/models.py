class Vulnerability:
    def __init__(self):
        self.cve_id = ''
        self.description = ''
        self.published_time = ''
        self.author = ''
        self.link = ''

    def setCveId(self, cve_id):
        self.cve_id = cve_id

    def setDescription(self, description):
        self.description = description

    def setPublishedTime(self, published_time):
        self.published_time = published_time

    def setAuthor(self, author):
        self.author = author

    def setLink(self, link):
        self.link = link

    def __str__(self) -> str:
        return '[' + self.cve_id + ', ' + self.description + ', ' + self.published_time + ', ' \
               + self.author + ', ' + self.link + ' ]'


class VulnType:
    def __init__(self):
        self.cwe_id = ''
        self.description = ''

    def setCweId(self, cwe_id):
        self.cwe_id = cwe_id

    def setDescription(self, description):
        self.description = description

    def __str__(self) -> str:
        return '[' + self.cwe_id + ', ' + self.description + ' ]'


class CVSS:
    def __init__(self):
        self.base_score = ''
        self.vector = ''

    def setBaseScore(self, basescore):
        self.base_score = basescore

    def setVector(self, vectorString):
        self.vector = vectorString

    def __str__(self) -> str:
        return '[' + str(self.base_score) + ', ' + self.vector + ' ]'


class Software:
    def __init__(self):
        self.software_name = ''
        self.vendor = ''
        self.version = ''
        self.url = ''
        self.description = ''
        self.language = ''
        self.update_time = ''
        self.fork = 0
        self.star = 0

    def setSoftwareName(self, software_name):
        self.software_name = software_name

    def setVendor(self, vendor):
        self.vendor = vendor

    def setVersion(self, version):
        self.version = version

    def setUrl(self, url):
        self.url = url

    def setDescription(self, description):
        self.description = description

    def setLanguage(self, language):
        self.language = language

    def setUpdateTime(self, update_time):
        self.update_time = update_time

    def setFork(self, fork):
        self.fork = fork

    def setStar(self, star):
        self.star = star

    def __str__(self) -> str:
        return '[' + self.software_name + ', ' + self.vendor + ', ' + self.version + ', ' + self.url + ', ' + \
               self.description + ', ' + self.language + ', ' + self.update_time + ', ' + str(self.fork) + ', ' + \
               str(self.star) + ' ]'


class Exploit(object):
    def __init__(self, title):
        self.eid = 0
        self.cve_id = ''
        self.description = title
        self.url = ''
        self.code_file = ''

    def setEid(self, eid):
        self.eid = eid

    def setCVE(self, cve):
        self.cve_id = cve

    def setDescription(self, description):
        self.description = description

    def setCodeFile(self, code_file):
        self.code_file = code_file

    def setUrl(self, url):
        self.url = url

    def __str__(self) -> str:
        return '[' + str(self.eid) + ', ' + self.cve_id + ', ' + self.description + ', ' + self.url + ', ' \
               + self.code_file + ' ]'


class Project:
    def __init__(self):
        self.project_name = ''
        self.artifact_id = ''
        self.description = ''
        self.version = ''
        self.group_id = ''
        self.url = ''

    def setName(self, project_name):
        self.project_name = project_name

    def setArtifactId(self, artifact_id):
        self.artifact_id = artifact_id

    def setDescription(self, description):
        self.description = description

    def setVersion(self, version):
        self.version = version

    def setGroupId(self, group_id):
        self.group_id = group_id

    def setUrl(self, url):
        self.url = url

    def __str__(self) -> str:
        return '[' + self.project_name + ', ' + self.artifact_id + ',' + self.description + ', ' + self.version + ', ' + self.group_id + ', ' + \
               self.url + ' ]'


class Diff:
    def __init__(self):
        self.url = ''
        self.cve_id = ''
        self.software = ''
        self.diff_file = ''
        self.language = ''

    def setUrl(self, url):
        self.url = url

    def setCVE(self, cve):
        self.cve_id = cve

    def setSoftware(self, software):
        self.software = software

    def setDiffFile(self, diff_file):
        self.diff_file = diff_file

    def setLanguage(self, language):
        self.language = language

    def __str__(self) -> str:
        return '[' + self.software + ', ' + self.cve_id + ', ' + self.url + ', ' + self.diff_file + ', ' + self.language + ' ]'


class Rule:
    def __init__(self):
        self.cwe_id = ''
        self.description = ''
        self.rule_file = ''

    def setCWEID(self, cwe_id):
        self.cwe_id = cwe_id

    def setDescription(self, description):
        self.description = description

    def setFile(self, file):
        self.rule_file = file

    def __str__(self) -> str:
        return '[' + self.cwe_id + ', ' + self.description + ', ' + self.rule_file + ' ]'


