# module for gathering artifacts related to web browsing history
# For ULR categorization WebShrinker API is being used
import os
import pyesedb
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
from base64 import urlsafe_b64encode
import hashlib
import requests
from datetime import datetime
import sqlite3
import json
from dateutil import parser
from PMADB import add_url_to_ela

global known_list
known_list = {}


def webshrinker_categories_v3(access_key, secret_key, url=b"", params={}):
    params['key'] = access_key
    params['taxonomy'] = 'webshrinker'
    if url:
        request = "categories/v3/{}?{}".format(urlsafe_b64encode(url).decode('utf-8'), urlencode(params, True))
    else:
        request = "categories/v3?{}".format(urlencode(params, True))
    request_to_sign = "{}:{}".format(secret_key, request).encode('utf-8')
    signed_request = hashlib.md5(request_to_sign).hexdigest()
    return "https://api.webshrinker.com/{}&hash={}".format(request, signed_request)


def url_is_email_provider(url):
    if "https://protonmail.com/" in url or "https://mail.protonmail.com/" in url:
        return True
    if "https://outlook.live.com/owa/" in url or "https://www.outlook.com/owa/" in url:
        return True
    if "https://mail.google.com/" in url:
        return True
    if "/roundcube/?_task=mail" in url:
        return True
    if "mail.yahoo.com" in url:
        return True
    if "http://gmail.com" in url or "www.google.com/gmail/" in url:
        return True

    return False


def get_url_category(URL, API_KEY, API_SECRET):
    if url_is_email_provider(URL):
        return "Electronic Mail Provider", "e-mail"
    # do not query for urls that were already queried (100 API calls free, $20 for 30,000 requests)
    if URL in known_list:
        return known_list[URL], "URL frequently visited. Category obtained from known urls."
    else:
        if URL:
            api_url = webshrinker_categories_v3(API_KEY, API_SECRET, bytearray(URL, 'utf-8'))
        else:
            api_url = webshrinker_categories_v3(API_KEY, API_SECRET, None)

        response = requests.get(api_url)

        status_code = response.status_code
        data = response.json()

        if status_code == 200:
            if URL:
                category = data["data"][0]["categories"][0]["label"]
                known_list[URL] = category
                return category, data
            else:
                return data, "All categories requested"
        elif status_code == 202:
            return None, "The website is being visited and the categories will be updated shortly"
        elif status_code == 400:
            return None, "Bad or malformed HTTP request"
        elif status_code == 401:
            return None, "Unauthorized - check your access and secret key permissions"
        elif status_code == 402:
            return None, "Account request limit reached"
        else:
            return None, "A general error occurred, try the request again"


def filetime_to_dt(ft):
    """Windows File Time timestamp convert to datetime"""
    EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
    HUNDREDS_OF_NANOSECONDS = 10000000
    return datetime.utcfromtimestamp((ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)


def analyse_edge_history(USER_FOLDER, API_KEY, API_SECRET):
    """ using pyesedb python wrapper around libesedb
    libesedb is a library to access the Extensible Storage Engine (ESE) Database File (EDB) format
    https://github.com/libyal/libesedb
    Edge stores many things including cookies and browsing history in this format
    """
    # TODO: on some systems there can be more than one WebCacheV??.dat file
    esedbfile = os.path.join(USER_FOLDER, 'AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat')
    db = pyesedb.open(esedbfile)
    for table in db.tables:
        if "HstsEntryEx" in table.get_name():
            # TODO: other tables may contain another interesting artifacts in the future versions
            for record in table.records:
                lastused = record.get_value_data_as_integer(5)
                url = record.get_value_data_as_string(6)
                if url[0] != ":":  # urls starting with colon have wrong date!
                    url = '.'.join(url.split('.')[::-1])  # urls are stored reversed
                    timestamp = filetime_to_dt(lastused)
                    cat, details = get_url_category(url, API_KEY, API_SECRET)
                    if cat:
                        add_url_to_ela(timestamp, url, cat, category_into_group(cat), "edge", None)
                    else:
                        print(details)
    db.close()


def analyse_chrome_history(USER_FOLDER, API_KEY, API_SECRET):
    history_db = os.path.join(USER_FOLDER, 'AppData/Local/Google/Chrome/User Data/Default/History')
    if os.path.exists(history_db):
        c = sqlite3.connect(history_db)
        cursor = c.cursor()
        select_statement = 'SELECT datetime(((visits.visit_time/1000000)-11644473600), "unixepoch"), urls.url, urls.title FROM urls, visits WHERE urls.id = visits.url;'
        cursor.execute(select_statement)

        results = cursor.fetchall()
        cnt = len(results)
        cntr = 0
        for timestamp, url, title in results:
            cat, details = get_url_category(url, API_KEY, API_SECRET)
            cntr += 1
            if cat:
                print(cntr, " of ", cnt, timestamp, cat, url)
                add_url_to_ela(parser.parse(timestamp), url, cat, category_into_group(cat), "chrome", title)
            else:
                print(cntr, " of ", cnt, details)


def category_into_group(category_label):
    """
    For the purpose of finding Potentially malicious activities I group into 3 categories:
    0 - work related
    1 - not related to work but not malicious
    2 - purely malicious
    """
    # TODO: Those assignments could be given to the end user of the tool
    if category_label == 'Business':
        return 0
    if category_label == 'Content Server':
        return 0
    if category_label == 'Economy and Finance':
        return 0
    if category_label == 'Education':
        return 0
    if category_label == 'Abortion':
        return 1
    if category_label == 'Adult':
        return 1
    if category_label == 'Advertising':
        return 1
    if category_label == 'Alcohol and Tobacco':
        return 1
    if category_label == 'Blogs and Personal Sites':
        return 1
    if category_label == 'Chat and Instant Messaging':
        return 1
    if category_label == 'Drugs':
        return 1
    if category_label == 'Entertainment':
        return 1
    if category_label == 'Food and Recipes':
        return 1
    if category_label == 'Gambling':
        return 1
    if category_label == 'Games':
        return 1
    if category_label == 'Health':
        return 1
    if category_label == 'Humor':
        return 1
    if category_label == 'Information Technology':
        return 0
    if category_label == 'Job Related':
        return 1
    if category_label == 'Messageboards and Forums':
        return 1
    if category_label == 'News and Media':
        return 1
    if category_label == 'Parked':
        return 1
    if category_label == 'Dating and Personals':
        return 1
    if category_label == 'Real Estate':
        return 1
    if category_label == 'Religion':
        return 1
    if category_label == 'Search Engines and Portals':
        return 1
    if category_label == 'Shopping':
        return 1
    if category_label == 'Social Networking':
        return 1
    if category_label == 'Sports':
        return 1
    if category_label == 'Streaming Media':
        return 1
    if category_label == 'Translation Sites':
        return 0
    if category_label == 'Travel':
        return 1
    if category_label == 'Uncategorized':
        return 1
    if category_label == 'Vehicles':
        return 1
    if category_label == 'Virtual Reality':
        return 1
    if category_label == 'Weapons':
        return 1
    if category_label == 'Deceptive':
        return 2
    if category_label == 'Hacking':
        return 2
    if category_label == 'Illegal Content':
        return 2
    if category_label == 'Malicious':
        return 2
    if category_label == 'Media Sharing':
        return 2
    if category_label == 'Proxy and Filter Avoidance':
        return 2
    if category_label == 'Electronic Mail Provider':
        return 2
