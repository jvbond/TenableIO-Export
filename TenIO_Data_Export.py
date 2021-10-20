import json, logging, time, collections
from datetime import datetime
from csv import DictWriter
from tenable.io import TenableIO
 
'''
Author: Jeff Bond
Date: 24 Sept, 2020

Create API keys for your user and enter that information into the akey and skey variables

Running this script will create two files in the directory you are working in:
    vulnerabilities.csv - Vulnerability export of the last 90 days
    assets.csv - Asset data export of the last 14 days


ToDo: Collect audit benchmark data
'''



akey = ''
skey = ''
output_file = 'vulnerabilities.csv'
sevs = ['critical','high', 'medium', 'low']
out_order = ['IPv4','HostName','OS','Severity','State','PluginID','PluginName','PluginFamily','PatchAvailable','Description','Synopsis','PluginOutput','Solution','FirstSeen','LastSeen','Port','CVE']
asset_File = 'assets.csv'
asset_order = ['ipv4s','ipv6s','hostnames','fqdns','created_at','last_scan_time','last_authenticated_scan_date','last_seen','operating_systems','installed_software']

# Time range within last 14 days  (epoch time)
time_range = (int(time.time()) -1209600)

logging.basicConfig(level=logging.DEBUG)
tio = TenableIO(akey, skey, 'retries=3')
 
 
def transform_vuln(vuln, delim='|'):
    '''
    Transforms a single vulnerability item into the expected format.
    '''
    plugin = vuln.get('plugin', dict())
    asset = vuln.get('asset', dict())
    port = vuln.get('port', dict())

    return {
        # Asset Attributes
        'IPv4': asset.get('ipv4'),
        'HostName': asset.get('hostname'),
        'OS': delim.join(asset.get('operating_system', list())).replace('\\r', ''),
 
        # Plugin Attributes
        'CVE': delim.join(plugin.get('cve', list())),
        'Description': plugin.get('description', ''),
        #'ExploitAvailable': plugin.get('exploit_available', 'false'),
        'PatchAvailable': plugin.get('has_patch'),
        'PluginFamily': plugin.get('family'),
        'PluginID': plugin.get('id'),
        'PluginName': plugin.get('name'),
        'Severity': plugin.get('risk_factor'),
        'Solution': plugin.get('solution'),
        'Synopsis': plugin.get('synopsis'),
 
        # Vuln Instance Attributes
        'FirstSeen': vuln.get('first_found'),
        'LastSeen': vuln.get('last_found'),
        'PluginOutput': vuln.get('output'),
        'State': vuln.get('state'),
 
        # Port Attributes
        'Port': port.get('port', 0),
        #'Protocol': port.get('protocol'),
        #'Service': port.get('service'),
    }


def write_to_csv(filename):
    '''
    Writes the vulnerability export to a CSV file
    '''
    fields = out_order
    counter = 0
 
    with open(filename, 'w', newline='') as reportfile:
        writer = DictWriter(reportfile, fields)
        writer.writeheader()
        for vuln in tio.exports.vulns(severity=list(sevs)):
            writer.writerow(transform_vuln(vuln))
            counter += 1
    return counter
 

'''
Asset Data Export
'''
def flatten(d, parent_key='', sep='.'):
    '''
    Flattens a nested dict.  Shamelessly ripped from
    `this <https://stackoverflow.com/a/6027615>`_ Stackoverflow answer.
    '''
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def asset_data(asset_File):
    '''
    Writes the asset list export to a CSV file
    '''
    fields2 = asset_order
    counter2 = 0
 
    with open(asset_File, 'w', newline='') as reportfile:
        writer2 = DictWriter(reportfile, fields2, extrasaction='ignore')
        writer2.writeheader()
        for item in tio.exports.assets(last_authenticated_scan_time=time_range):

            # We need the vulnerability dictionary flattened out and all of the
            # lists converted into a pipe-delimited string.
            flat = flatten(item)
            for k, v in flat.items():
                if isinstance(v, list):
                    flat[k] = '|'.join([str(i) for i in v])
                if k == 'tags':
                    flat[k] = '|'.join(['{}:{}'.format(i['key'], i['value']) for i in v])


            writer2.writerow(flat)
            counter2 += 1
    return counter2


    
 
if __name__ == '__main__':
    start_time = time.time()
    rows = write_to_csv(output_file)
    tot_assets = asset_data(asset_File)
    elapsed = time.gmtime(time.time() - start_time)
    print('\n'.join([
        'Runtime : {}'.format(time.strftime("%H:%M:%S", elapsed)),
        'Entries : {}'.format(rows),
        'Assets : {}'.format(tot_assets)
    ]))
