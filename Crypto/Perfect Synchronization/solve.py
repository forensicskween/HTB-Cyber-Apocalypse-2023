import pandas as pd
import requests
from bs4 import BeautifulSoup
from collections import Counter


wikiurl="https://en.wikipedia.org/wiki/Letter_frequency"
table_class="wikitable sortable jquery-tablesorter"

def get_dict(wikiurl,table_class):
    response=requests.get(wikiurl)
    soup = BeautifulSoup(response.text, 'html.parser')
    indiatable=soup.find('table',{'class':"wikitable"})
    df=pd.read_html(str(indiatable))
    df=pd.DataFrame(df[0])
    df.columns=df.columns.droplevel(0)
    df=df.reset_index(drop=True)
    df['Texts']=df['Texts'].apply(lambda x: float(x.replace('%','')))
    out_dict = list(df.sort_values('Texts',ascending=False)['Letter'])
    return out_dict

def parse_data(data, dict_map):
    data = [i.strip() for i in data]
    unique_vals = list(set(data))
    #len(unique_vals) == 30
    plain_vals = [' '] + dict_map + [i for i in '{_}']
    assert len(plain_vals) == len(unique_vals)
    counts = Counter(data)
    dict_items = {k: v for k, v in sorted(dict(counts).items(), key=lambda item: item[1],reverse=True)}
    dict_items.update(zip(dict_items, plain_vals))
    new_data =[]
    for val in data:
        c = dict_items[val]
        new_data.append(c)
    return ''.join(new_data)


with open('files/output.txt','r') as inf:
    data = inf.readlines()

dict_map = get_dict(wikiurl,table_class)
cipher = parse_data(data,dict_map)

with open('files/cipher.txt','w') as outf:
    outf.write(cipher)


