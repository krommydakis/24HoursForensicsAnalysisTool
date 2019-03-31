from PMADB import get_url_stats, get_pmacategory_count
from math import trunc


def report():
    # try is chere to check ElasticSearch connection
    try:
        # Initial percentage of Atack Scenarios:
        ATTACKS = {
            "A_DATA_EXFILTRATION": 0,
            "B_DATA_ALTERATION": 0,
            "C_DATA_DESTRUCTION": 0,
            "D_APT": 0,
            "E_LOGIC_BOMB": 0,
            "F_STOLEN_CRED": 0,
            "G_LIMIT_PROD": 0,
            "H_ANTI_FORENSIC": 0
        }
        # Initially I wanted to go chronologically through all artifacts, witch sth like:
        # q = 'SELECT category FROM PMA ORDER BY timestamp'
        # and based on sequence and occurrence of artifacts in a time proximity raise percentage for each attack scenario
        # but I decided to just assign each PMA to each attack scenario:
        # TODO: this is an example algorythm
        A = [3, 4, 5, 6, 17, 20, 21]
        B = [11]
        C = [10]
        D = [7, 8, 9, 12, 14]
        E = [22]
        F = [16]
        H = [13, 15, 19, 24]
        # if category counts are not zero then
        count_a = 0
        for pma in A:
            count_a += get_pmacategory_count(pma)
        if count_a:
            ATTACKS['A_DATA_EXFILTRATION'] = count_a

        count_b = get_pmacategory_count(11)
        if count_b:
            ATTACKS['B_DATA_ALTERATION'] = count_b

        count_c = get_pmacategory_count(10)
        if count_c:
            ATTACKS['C_DATA_DESTRUCTION'] = count_c

        count_d = 0
        for pma in D:
            count_d += get_pmacategory_count(pma)
        if count_d:
            ATTACKS['D_APT'] = count_d

        count_e = get_pmacategory_count(22)
        if count_e:
            ATTACKS['E_LOGIC_BOMB'] = count_e

        count_f = get_pmacategory_count(16)
        if count_f:
            ATTACKS['F_STOLEN_CRED'] = count_f

        count_h = 0
        for pma in H:
            count_h += get_pmacategory_count(pma)
        if count_h:
            ATTACKS['H_ANTI_FORENSIC'] = count_h

        # 'Limited Productivity' attack probability percentage could be done as
        # proportion of non work related browsing to all browsing.
        # cnt_wrkrel, cnt_notrel, cnt_malici = get_url_stats()
        # BAD = cnt_notrel * 1.0 + cnt_malici * 1.0
        # ALL = cnt_wrkrel * 1.0 + cnt_notrel * 1.0 + cnt_malici * 1.0
        # PERCENTAGE = BAD / ALL * 100

        count_g = get_pmacategory_count(25)
        if count_g:
            ATTACKS['G_LIMIT_PROD'] = count_g

        return ATTACKS
    except:
        return "Unable to connect to ElasticSearch!"
