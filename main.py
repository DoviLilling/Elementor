from tinydb import TinyDB, Query
from urllib import request, parse
import json
import datetime
import pandas as pd

db = TinyDB('db.json')
tab_site = db.table('site')
tab_voting = db.table('voting')
tab_site_classification = db.table('site_classification')

virus_total_api_key = '5657d41806b489e118ded28067fc42833502485b7d77d72cac876889f01d843b'
virus_total_scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
virus_total_report_url = 'https://www.virustotal.com/vtapi/v2/url/report?'

request.urlretrieve("https://elementor-pub.s3.eu-central-1.amazonaws.com/Data-Enginner/Challenge1/request1.csv", "request1.csv")

with open("request1.csv") as sites:
    for site in sites:
        need_to_update = False
        need_to_insert = False
        url = site.strip()
        try:
            site_rec = db.search(tab_site.URL == url)
            # TODO: add selection of update_date, check if 30 mins, raise need_to_update flag if true
        except AttributeError:
            print('site ' + url + ' does not exist in DB. Adding...')
            need_to_insert = True
        if need_to_update or need_to_insert:
            scan_data = {'apikey': virus_total_api_key,
                         'url': url}
            scan_data_encoded = parse.urlencode(scan_data).encode('ascii')
            res = request.urlopen(request.Request(virus_total_scan_url, scan_data_encoded))
            try:
                scan_res = json.loads(res.read())
                scan_id = scan_res['scan_id']
                scan_id_exists = True
            except json.decoder.JSONDecodeError:
                scan_id_exists = False
            if scan_id_exists:
                rep_params = parse.urlencode({'apikey': virus_total_api_key,
                                              'resource': scan_id,
                                              'allinfo': True})
                res = request.urlopen(request.Request(virus_total_report_url + rep_params))
                try:
                    report = json.loads(res.read())
                    report_exists = True
                except json.decoder.JSONDecodeError:
                    report_exists = False
                if report_exists:
                    site_update_date = datetime.datetime.utcnow().__str__()
                    scans = report['scans'].values()
                    for scan in scans:
                        scan['result'] = scan['result'].replace(' site', '')
                    url_data = pd.DataFrame(scans).groupby('result').count()
                    print(url_data)
                    url_data = url_data.to_dict()
                    url_data = url_data['detected']
                    print(url_data)
                    if 'malicious' in url_data or 'phishing' in url_data or 'malware' in url_data:
                        site_category = 'risk'
                    else:
                        site_category = 'safe'


                    # voting_type =
                    # voting_votes =
            if need_to_update:
                None
                # TODO: update values to DB
            elif need_to_insert:
                tab_site.insert({'URL': url, 'category': site_category, 'update_date': site_update_date})
                for vote_type in url_data:
                    tab_voting.insert({'URL': url, 'voting_type': vote_type, 'votes': url_data[vote_type]})