import urllib.request
from tinydb import TinyDB, Query

db = TinyDB('db.json')
tab_site = db.table('site')
tab_voting = db.table('voting')
tab_site_classification = db.table('site_classification')

virusTotalApiKey = '5657d41806b489e118ded28067fc42833502485b7d77d72cac876889f01d843b'
virusTotalScanURL = 'https://www.virustotal.com/vtapi/v2/url/scan'
virusTotalReportURL = 'https://www.virustotal.com/vtapi/v2/url/report?'

urllib.request.urlretrieve("https://elementor-pub.s3.eu-central-1.amazonaws.com/Data-Enginner/Challenge1/request1.csv", "request1.csv")

with open("request1.csv") as sites:
    for site in sites:
        need_to_update = False
        need_to_insert = False
        URL = site.strip()
        try:
            site_rec = db.search(tab_site.URL == URL)
            # TODO: add selection of update_date, check if 30 mins, raise need_to_update flag if true
        except AttributeError:
            print('site ' + URL + ' does not exist in DB. Adding...')
            need_to_insert = True
        if need_to_update or need_to_insert:
            scanData = {'apikey': virusTotalApiKey,
                        'url': URL}
            scanDataEncoded = urllib.parse.urlencode(scanData)
            res = urllib.request.urlopen(urllib.request.Request(virusTotalScanURL, scanDataEncoded.encode('ascii')))
            scan = res.read()
            print(scan)
            # TODO: get report
        if need_to_update:
            None
            # TODO: update values to DB
        elif need_to_insert:
            None
            # TODO: insert values to DB