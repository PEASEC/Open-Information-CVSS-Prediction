from nvd_connector.cvss.cvssv2 import CVSSV2
from nvd_connector.cvss.cvssv3 import CVSSV3


class NVDEntry:
    '''
    Implements the NVDEntry class to represent NVD information in a structured form.
    '''
    def __init__(self, cve_dict: dict):
        self.id: str = cve_dict['cve']['CVE_data_meta']['ID']
        self.year: int = int(self.id[4:8])

        problemtype_data: dict = cve_dict['cve']['problemtype']['problemtype_data']
        self.reference_data: dict = cve_dict['cve']['references']['reference_data']
        description_data: dict = cve_dict['cve']['description']['description_data']

        self.cwe: set = {cwe['value'] for data in problemtype_data for cwe in data['description']}
        self.references: list = [e['url'] for e in self.reference_data]
        self.description: list = [e['value'] for e in description_data]
        self.rejected: bool = any('** REJECT **' in d for d in self.description)

        self.cpe: list = cve_dict['configurations']['nodes']
        if 'baseMetricV2' in cve_dict['impact'].keys():
            self.cvssv2: CVSSV2 = CVSSV2(cve_dict['impact']['baseMetricV2']['cvssV2'])
        else:
            self.cvssv2 = None
        if 'baseMetricV3' in cve_dict['impact'].keys():
            self.cvssv3: CVSSV3 = CVSSV3(cve_dict['impact']['baseMetricV3']['cvssV3'])
        else:
            self.cvssv3 = None

    def __eq__(self, other):
        if isinstance(other, NVDEntry):
            return self.cwe == other.cwe and \
                   self.cpe == other.cpe and \
                   self.cvssv2 == other.cvssv2 and \
                   self.cvssv3 == other.cvssv3
        return False

    def __hash__(self):
        return hash(self.id)

    def __repr__(self):
        return str(self.__dict__)

    def __str__(self):
        return self.__repr__()
