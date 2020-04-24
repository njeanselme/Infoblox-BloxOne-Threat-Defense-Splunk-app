# encoding = utf-8
import os
import sys
import time
import datetime
import json
import base64
import requests
import splunklib.client as client
import splunklib.results as splunk_results

def validate_input(helper, definition):
    pass

def collect_events(helper, ew):

    # Get variables
    
    apikey = helper.get_arg('apikey') + ":"
    interval = helper.get_arg('interval')
    helper.get_input_type()
    loglevel = helper.get_log_level()
    proxy_settings = helper.get_proxy()
    account = helper.get_arg('global_account')
    username = account['username']
    password = account['password']

    helper.log_debug("Parameters correctly obtained")

    # for each entry in KVstore not searched
    service = client.connect(username=username, password=password)
    helper.log_debug("Connection to splunk API OK")
    kwargs_oneshot = {"earliest_time": "2000-01-01T00:00:00.000-00:00", "latest_time": "now", "count": 40}
    
    searchquery_oneshot = "|inputlookup botdc_distinct_threat_indicators | stats values(enriched) as enriched, values(feed_type) as feed_type, min(event_time) as first_time_seen, sum(count) as count by threat_indicator | where NOT (isnull(enriched) OR match(enriched,\"1\"))| sort - count"

    oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
    
    helper.log_debug("Splunk search executed properly")

    # Get the results and display them using the ResultsReader
    reader = splunk_results.ResultsReader(oneshotsearch_results)
    for item in reader:
        threat_indicator = item.get('threat_indicator')
        if item.get('feed_type') == "IP Address":
            threat_indicator_type = "ip"
        elif item.get('feed_type') == "FQDN":
            threat_indicator_type = "host"

        # Do a Dossier search
        helper.log_info("Start perform an Infoblox Dossier Search for " + threat_indicator)

        url = "https://platform.activetrust.net:8000/api/services/intel/lookup/indicator/"
        url = url + threat_indicator_type
        url = url + "?value=" + threat_indicator + "&wait=true"
        method="GET"
        auth = base64.encodebytes(('%s:' % (apikey)).encode('utf8')).decode('utf8').replace('\n', '')

        headers = {
       'Authorization':'Basic %s' % auth,
       'Content-Type':'application/x-www-form-urlencoded',
       'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36',
       'Cache-Control': 'no-cache'
        }
        
        if not proxy_settings:
            response = requests.get(url, headers=headers, cookies=None, verify=True, timeout=(600,600), stream=True)
        else:
            response = requests.get(url, headers=headers, cookies=None, verify=True, timeout=(600,600), proxies=proxy_settings, stream=True)
        
        if response.encoding is None:
            response.encoding = 'utf-8'
        if response.text:
            try:
                r_json=json.loads(response.text)
            except:
                raise Exception("Unable to load into a json format")

            data = json.dumps(r_json)
            data = data.replace("\"host\":","\"hostname\":")
            data = data.replace("\"source\":","\"src\":")
            
            helper.log_debug("data: " + data)
            
            data = json.loads(data)

            if "results" in data.keys():
                for result in data["results"]:
                    if "params" in result.keys():
                        if "src" in result["params"].keys():
                            if "data" in result.keys():
                                
                                if result["params"]["src"] == "atp":
                                    for threat in result["data"]["threat"]:
                                        threat["threat_indicator"] = threat_indicator
                                        threat["threat_indicator_type"] = threat_indicator_type
                                        result_data= json.dumps(threat)
                                        event = helper.new_event(source=result["params"]["src"], index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data = result_data)
                                        ew.write_event(event)

                                elif result["params"]["src"] == "malware_analysis":
                                    if "details" in result["data"].keys():
                                        if "detected_communicating_samples" in result["data"]["details"].keys():
                                            for malware_analysis in result["data"]["details"]["detected_communicating_samples"]:
                                                malware_analysis["threat_indicator"] = threat_indicator
                                                malware_analysis["threat_indicator_type"] = threat_indicator_type
                                                malware_analysis["threat_indicator_type"] = "detected_communicating_samples"
                                                result_data= json.dumps(malware_analysis)
                                                event = helper.new_event(source=result["params"]["src"], index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data = result_data)
                                                ew.write_event(event)
    
                                        if "detected_downloaded_samples" in result["data"]["details"].keys():
                                            for malware_analysis in result["data"]["details"]["detected_downloaded_samples"]:
                                                malware_analysis["threat_indicator"] = threat_indicator
                                                malware_analysis["threat_indicator_type"] = threat_indicator_type
                                                malware_analysis["threat_indicator_type"] = "detected_downloaded_samples"
                                                result_data= json.dumps(malware_analysis)
                                                event = helper.new_event(source=result["params"]["src"], index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data = result_data)
                                                ew.write_event(event)
    
                                        if "detected_urls" in result["data"]["details"].keys():
                                            for malware_analysis in result["data"]["details"]["detected_urls"]:
                                                malware_analysis["threat_indicator"] = threat_indicator
                                                malware_analysis["threat_indicator_type"] = threat_indicator_type
                                                malware_analysis["threat_indicator_type"] = "detected_urls"
                                                result_data= json.dumps(malware_analysis)
                                                event = helper.new_event(source=result["params"]["src"], index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data = result_data)
                                                ew.write_event(event)        

                                elif result["params"]["src"] == "pdns":
                                    for pdns in result["data"]["items"]:
                                        pdns["threat_indicator"] = threat_indicator
                                        pdns["threat_indicator_type"] = threat_indicator_type
                                        result_data= json.dumps(pdns)
                                        event = helper.new_event(source=result["params"]["src"], index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data = result_data)
                                        ew.write_event(event)

                                else:
                                    result["data"]["threat_indicator"] = threat_indicator
                                    result["data"]["threat_indicator_type"] = threat_indicator_type
                                    result_data= json.dumps(result["data"])
                                    event = helper.new_event(source=result["params"]["src"], index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data = result_data)
                                    ew.write_event(event)

                                searchquery_oneshot_update = "|makeresults | eval threat_indicator=\"" + threat_indicator + "\" | eval enriched=1 | outputlookup botdc_distinct_threat_indicators append=true createinapp=true"
                                oneshotsearch_update_results = service.jobs.oneshot(searchquery_oneshot_update, **kwargs_oneshot)

        helper.log_info("Completed an Infoblox Dossier Search for "+ threat_indicator)
