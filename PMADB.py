#  PMA DB (Potentially Malicious Actions DataBase) module
#  Contains helper methods used to categorize Artifacts and methods used for indexing them in ElasticSearch
from elasticsearch import Elasticsearch
import configparser

global es
config = configparser.ConfigParser()
config.read('config.ini')
es = Elasticsearch([{'host': config['ELASTIC_SEARCH']['HOST'], 'port': config['ELASTIC_SEARCH']['PORT']}])


def add_action(timestamp, categorynum, description):
    pma = {
        "@timestamp": timestamp,
        "categorynum": categorynum,
        "description": description
    }
    idxstat = es.index(index='potentially_malicious_actions', doc_type='PMA', body=pma)
    if idxstat['_shards']['successful'] == 1:
        print('.', end='')


def add_software(timestamp, name):
    categorynum = categorize_software(name)
    if categorynum:
        add_action(timestamp, categorynum, "User installed {}!".format(name))


def categorize_software(name):
    if name in ["TeamViewer", "AnyDesk", "UltraVNC", "TightVNC", "UltraViewer", "TigerVNC"]:
        return 9
    elif name in ["Hyper-V", "VirtualBox", "VMLite Workstation", "VMWare Server"]:
        return 13
    else:
        return None


def add_url_to_ela(timestamp, url, urlcategory, urlgroup, browser, title):
    urldoc = {
        "@timestamp": timestamp,
        "url": url,
        "urlcategory": urlcategory,
        "urlgroup": urlgroup,
        "browser": browser,
        "title": title
    }
    idxstat = es.index(index='url', doc_type='url', body=urldoc)
    #print(idxstat)

    if urlgroup == 1:
        add_action(timestamp, 23, "Limited Productivity! Accessed non-business related website: {}".format(url))
    if urlgroup == 2:
        if urlcategory == 'Deceptive' or urlcategory == 'Hacking' \
                or urlcategory == 'Illegal Content' or urlcategory == 'Malicious':
            info = "Possible APT may follow!"
            add_action(timestamp, 18, "Accessed {} website({}). {}".format(urlcategory, url, info))
        if urlcategory == 'Media Sharing':
            info = "Possible Data Exfiltration!"
            add_action(timestamp, 3, "Accessed {} website({}). {}".format(urlcategory, url, info))
        if urlcategory == 'Proxy and Filter Avoidance':
            info = "Common Anti-Forensics technique!"
            add_action(timestamp, 24, "Accessed {} website({}). {}".format(urlcategory, url, info))
        if urlcategory == 'Electronic Mail Provider':
            info = "High possibility of Data Exfiltration!"
            add_action(timestamp, 5, "Accessed {} website({}). {}".format(urlcategory, url, info))


# ################ Elastic Search ############## #
def create_indexes():
    indexes = ['potentially_malicious_actions', 'url']
    for i in indexes:
        create_index(es, i)


def create_index(es, IDX_NAME):
    if es.indices.exists(IDX_NAME):
        es.indices.delete(index=IDX_NAME)
        print('Dropping {} index.'.format(IDX_NAME))

    mappings = {}
    if IDX_NAME == 'url':
        mappings = mappings_urls
    if IDX_NAME == 'potentially_malicious_actions':
        mappings = mappings_PMA

    index_settings = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        },
        "mappings": mappings
    }
    es.indices.create(index=IDX_NAME, ignore=400, body=index_settings)
    print('Created index: {}'.format(IDX_NAME))


mappings_urls = {
            "url": {
                "properties": {
                    "url": {"type": "string"},
                    "@timestamp": {"type": "date"},
                    "urlcategory": {"type": "keyword"},
                    "urlgroup": {"type": "short"},
                    "browser": {"type": "keyword"},
                    "title": {"type": "string"}
                }
            }
        }

mappings_PMA = {
      "PMA": {
        "properties": {
            "@timestamp": {"type": "date"},
            "categorynum": {"type": "short"},
            "description": {"type": "text", "fields": {
                    "keyword": {"type": "keyword", "ignore_above": 256}}
                            }

                    }
            }
        }

# ##################### #


def get_pmacategory_count(categorynum):
    res = es.count(index="potentially_malicious_actions", doc_type="PMA",
                   body={"query": {"term": {"categorynum": str(categorynum)}}})
    count = res['count']
    return count


def get_url_stats():
    res = es.count(index="url", doc_type="url", body={"query": {"term": {"urlgroup": "0"}}})
    cnt_wrkrel = res['count']
    res = es.count(index="url", doc_type="url", body={"query": {"term": {"urlgroup": "1"}}})
    cnt_notrel = res['count']
    res = es.count(index="url", doc_type="url", body={"query": {"term": {"urlgroup": "2"}}})
    cnt_malici = res['count']
    return cnt_wrkrel, cnt_notrel, cnt_malici


def create_report_document(attacks_array):
    for attack, percentage in attacks_array.items():
        a = {"attack": attack, "percentage": percentage}
        es.index(index='report', doc_type='report', body=a)
