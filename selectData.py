import sqlite3
import pandas as pd
conn = sqlite3.connect('sites.db', isolation_level=None)
c = conn.cursor()
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)

# c.execute('UPDATE SITE SET update_date = ?', ('2020-10-09 11:01:35.581752',))

print('site table:')
print('~~~~~~~~~~~')
print(pd.read_sql_query('SELECT * FROM SITE', conn))
print()
print('voting table:')
print('~~~~~~~~~~~~~')
print(pd.read_sql_query('SELECT * FROM VOTING', conn))
print()
print('site_classification table:')
print('~~~~~~~~~~~~~~~~~~~~~~~~~~')
print(pd.read_sql_query('SELECT * FROM SITE_CLASSIFICATION', conn))