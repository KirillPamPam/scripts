import sys
import time
import requests
import pandas as pd
import urllib3
from requests import adapters
import ssl
from urllib3 import poolmanager


class TLSAdapter(adapters.HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        """Create and initialize the urllib3 PoolManager."""
        ctx = ssl.create_default_context()
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        self.poolmanager = poolmanager.PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_version=ssl.PROTOCOL_TLS,
            ssl_context=ctx)


NO_PRODUCTS = 'No products'
NOT_FOUND = 'Not found'
PRODUCTS_NO_RULES = 'There are products but no rules'
OK = 'Ok'

td_props = [('border', '1px solid black')]
table_style = [
    dict(selector='th', props=td_props),
    dict(selector='td', props=td_props)
]


def get_families(csv_file_path):
    families_df = pd.read_csv(csv_file_path, usecols=['family_id'])
    return families_df.drop_duplicates().values.tolist()


def handle_family_info(response, family_id, family_status_map, show_valid):
    family_info = response.json()[0]
    family_products = family_info['products']
    rules = family_info['rules']

    if not family_products:
        family_status_map[family_id] = NO_PRODUCTS
    else:
        if not rules:
            family_status_map[family_id] = PRODUCTS_NO_RULES
        elif show_valid:
            family_status_map[family_id] = OK


def validate_families(families, url, show_valid):
    print('Families count: {}'.format(len(families)))
    family_status_map = {}
    for i, family in enumerate(families):
        if i == 100:
            break
        family_id = family[0]
        print("Processing {} family".format(family_id))
        session = requests.sessions.Session()
        session.mount('https://', TLSAdapter())
        response = session.get(url.format(family_id), params={'showProducts': 'true'}, verify=False)
        if response.status_code == 404:
            family_status_map[family_id] = NOT_FOUND
        elif response.status_code == 200:
            handle_family_info(response, family_id, family_status_map, show_valid)
        time.sleep(0.5)
    if family_status_map:
        generate_report(family_status_map, show_valid)


def highlight_status(status):
    color = 'white'
    if status == NO_PRODUCTS or status == NOT_FOUND:
        color = 'red'
    elif status == PRODUCTS_NO_RULES:
        color = 'yellow'

    return 'background-color: %s' % color


def count_families(family_status_map, property):
    return sum(value == property for value in family_status_map.values())


def generate_report(family_status_map, show_valid):
    print("Generating report...")
    df_report = pd.DataFrame({'family': list(family_status_map.keys()), 'status': list(family_status_map.values())})
    report = df_report.style\
        .set_table_styles(table_style)\
        .set_table_attributes('style="border-collapse: collapse"')\
        .hide_index()\
        .applymap(highlight_status, subset=['status']).render()
    if show_valid:
        report += '<h2>Valid families: {}</h2>'.format(count_families(family_status_map, OK))
    report += '<h2>Families without products: {}</h2>'.format(count_families(family_status_map, NO_PRODUCTS))
    report += '<h2>Not found families: {}</h2>'.format(count_families(family_status_map, NOT_FOUND))
    report += '<h2>Families with products but without rules: {}</h2>'.format(count_families(family_status_map, PRODUCTS_NO_RULES))
    f = open("report.html", "w")
    f.write(report)
    f.close()
    print("Report is ready")


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    args = sys.argv[1:]
    family_service_url = args[0] + '{}'
    file_path = args[1]
    show_valid = args[2] == 'True'
    validate_families(get_families(file_path), family_service_url, show_valid)
