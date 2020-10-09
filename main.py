import os
import sqlite3
from urllib import request, parse
import json
import datetime

if os.path.exists('sites.db'):
    conn = sqlite3.connect('sites.db')
    c = conn.cursor()
else:
    conn = sqlite3.connect('sites.db')
    c = conn.cursor()
    c.execute("CREATE TABLE SITE (url text PRIMARY KEY, id text, category text, update_date text)")
    c.execute("CREATE TABLE VOTING (url text, voting_type text, votes integer, PRIMARY KEY(url, voting_type))")
    c.execute(
        "CREATE TABLE SITE_CLASSIFICATION (url text, classification text, votes integer, PRIMARY KEY(url, classification))")

virus_total_url = 'https://www.virustotal.com/api/v3/urls'
virus_total_header = {'x-apikey': '5657d41806b489e118ded28067fc42833502485b7d77d72cac876889f01d843b'}
# page of wrong APIs: https://developers.virustotal.com/reference. Third result of Google on searching "virustotal api python"

problematic_results = ['malicious', 'phishing', 'malware']

request.urlretrieve("https://elementor-pub.s3.eu-central-1.amazonaws.com/Data-Enginner/Challenge1/request1.csv",
                    "request1.csv")

def get_site_data(url):
    get_id_data = parse.urlencode({'url': url}).encode('ascii')
    res = request.urlopen(request.Request(virus_total_url, get_id_data, virus_total_header))
    try:
        id_res = json.loads(res.read())
        url_id = id_res['data']['id'].split('-')[1]
        url_id_exists = True
    except json.decoder.JSONDecodeError:
        url_id_exists = False
    if url_id_exists:
        res = request.urlopen(request.Request(virus_total_url + '/' + url_id, headers=virus_total_header))
        data = json.loads(res.read())
        return data['data']


def get_site_category(last_analysis_stats):
    category = 'safe'
    for k, v in last_analysis_stats.items():
        if k in problematic_results and v > 0:
            category = 'risk'
    return category


def get_category_counts(categories):
    cat_counts = {}
    for k, v in categories.items():
        cat_counts[v] = 1 if v not in cat_counts.keys() else cat_counts[v] + 1
    return cat_counts


def delete_records(url_as_touple):
    c.execute('DELETE FROM VOTING WHERE url = ?', url_as_touple)
    c.execute('DELETE FROM SITE_CLASSIFICATION WHERE url = ?', url_as_touple)
    c.execute('DELETE FROM SITE WHERE url = ?', url_as_touple)


with open("request1.csv") as sites:
    for site in sites:
        need_to_update = False
        need_to_insert = False
        url = site.strip()
        url_for_select = (url,)
        site_update_time = c.execute("SELECT update_date FROM SITE WHERE url = ?", url_for_select).fetchall()
        if len(site_update_time) == 0:
            print('site ' + url + ' does not exist in DB. Adding...')
            need_to_insert = True
        else:
            site_update_time = datetime.datetime.strptime(site_update_time[0][0], '%Y-%m-%d %H:%M:%S.%f')
            if (datetime.datetime.utcnow() - site_update_time).total_seconds() / 60 > 30:
                print('site ' + url + ' is out-of-date. Updating...')
                need_to_update = True
            else:
                print('site ' + url + ' is just fine, last update was at ' + str(site_update_time))
        if need_to_update or need_to_insert:
            url_data = get_site_data(url)
            if len(url_data) > 0:
                site_update_date = datetime.datetime.utcnow()
                url_id_ins = url_data['id'].split('-')[1]
                site_category = get_site_category(url_data['attributes']['last_analysis_stats'])
                total_votes = url_data['attributes']['total_votes']
                category_counts = get_category_counts(url_data['attributes']['categories'])
            if need_to_update:
                delete_records(url_for_select)
            values = [url, url_id_ins, site_category, site_update_date]
            c.execute('INSERT INTO SITE (url, id, category, update_date) VALUES (?, ?, ?, ?)', values)
            c.executemany('INSERT INTO VOTING (url, voting_type, votes) VALUES (?, ?, ?)', [(url, k, v) for k, v in total_votes.items()])
            c.executemany('INSERT INTO SITE_CLASSIFICATION (url, classification, votes) VALUES (?, ?, ?)', [(url, k, v) for k, v in category_counts.items()])
            conn.commit()
            if need_to_insert:
                print('Added.')
            elif need_to_update:
                print('Updated.')
