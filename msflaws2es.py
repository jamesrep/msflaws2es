# James Dickson 2021
# This little script may be used to ingest Patch Tuesday data from microsofts' API to Elasticsearch
# See https://api.msrc.microsoft.com/cvrf/v2.0/swagger/index for API doc
import json
import os
import argparse
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.connection import create_ssl_context
import urllib.request as urlrequest
from dateutil.relativedelta import relativedelta

def ingestElasticsearch(esConnection, esIndex, esTimestamp, doc, dtNow, uniqueId):
    print("[+] shipping to elasticsearch index", esIndex)
    
    strFinalIndex = esIndex.replace("#yyyy#", str(dtNow.year))
    strFinalIndex = strFinalIndex.replace("#mm#", str(dtNow.month))
    strFinalIndex = strFinalIndex.replace("#dd#", str(dtNow.day))

    if(esTimestamp == None):
        esTimestamp = "@timestamp"
    
    # Set the timestamp to the last revision
    if(doc['RevisionHistory'] != None):
        doc[esTimestamp] = doc['RevisionHistory'][len(doc['RevisionHistory'])-1]['Date']
    else:
        doc[esTimestamp] = dtNow

    highestBaseScore = 0.0
    highestTemporalScore = 0.0

    # Quite handy to parse out the highest scores.
    if(doc['CVSSScoreSets'] != None):
        for bscore in doc['CVSSScoreSets']:
            tmpScore = float(bscore['BaseScore'])

            if(tmpScore > highestBaseScore):
                highestBaseScore = tmpScore

            tmpScore = float(bscore['TemporalScore'])
            if(tmpScore > highestTemporalScore):
                highestTemporalScore = tmpScore

        doc['highestbasescore'] = highestBaseScore
        doc['highesttemporalscore'] = highestTemporalScore

    doc['ingesttime'] = dtNow           # Well, maybe not nice to hard code this.
    doc['vulnidentifier'] = uniqueId    # Well, maybe not nice to hard code this.

    res = esConnection.index(index=strFinalIndex, body=doc)
    # print(res['result'])

def getHistoryFileDir():
    strScriptPath = os.path.dirname( os.path.abspath(__file__))
    return strScriptPath + os.path.sep + "history" 

# Just returns the path to the history file
def getHistoryFilePath(strMonth):
    return getHistoryFileDir() + os.path.sep + strMonth.replace(".", "_").replace("/", "_").replace("\\", "_") + ".txt"

# strMonth is on form 2021-Aug. The history files are placed in the history folder 
def getDocForMonth(strMonth):
    strHistoryFile =  getHistoryFilePath(strMonth)

    if(os.path.exists(strHistoryFile)):
        with open(strHistoryFile, encoding="utf-8") as f:
            strLastUpdate = f.read() 
            jDoc = json.loads(strLastUpdate)

            return jDoc

    return None 

# Dump the json to file
def writeDocForMonth(strMonth, jDoc):
    strHistoryFile =  getHistoryFilePath(strMonth)

    # First remove the old file if it is there. If not there make sure the directory exists.
    if(os.path.exists(strHistoryFile)):
        os.remove(strHistoryFile)
    else:
        strDir = getHistoryFileDir()
        if not os.path.exists(strDir):
            os.makedirs(strDir)        

    with open(strHistoryFile, encoding="utf-8", mode="w+") as f:
        strDoc = json.dumps(jDoc, default=str)
        f.write(strDoc)
        f.flush()

    return None     

# TODO: this is really slow, hence we would save some time by first index the dictionary instead of linear search
def findRevision(jDoc, lastRevision, strCVEToTest, strTitleToTest):
    for v in jDoc['Vulnerability']:
        strCVE = ""
        
        if(v['CVE'] != None):
            strCVE = v['CVE']

        if(strCVE == strCVEToTest):
            strTitle = ""
            if(v['Title'] != None):
                if('Value' in v['Title']):
                    strTitle = v['Title']['Value']
                else:
                    strTitle = str(v['Title'])


            if(strTitle == strTitleToTest):
                lastRevision = v['RevisionHistory'][len(v['RevisionHistory'])-1]  
                return lastRevision
           
def createElasticConnection(args):
    if args.elastichost != None :
        if(args.elastictls):
            bVerifyCerts = True
            elasticport = 9200

            if args.elastictimefield == None:
                args.elastictimefield="@timestamp"

            if args.elasticport:
                elasticport = int(args.elasticport)

            if args.elasticskipcert :
                bVerifyCerts = False

            esConnection = Elasticsearch(args.elastichost, verify_certs=bVerifyCerts, http_auth=(args.elasticuser, args.elasticpassword), scheme="https",port=elasticport)
        else:
            esConnection = Elasticsearch(args.elastichost)  

        return esConnection

def getMsFlaws(strUrl, strUserAgent, strProxy):
    try:
        headers = {"User-Agent": strUserAgent}
        proxy_handler = urlrequest.ProxyHandler({'https': strProxy})

        if(strProxy != None):
            print("[+] using proxy ", strProxy, " for ", strUrl)
            opener = urlrequest.build_opener(proxy_handler)
        else:
            opener = urlrequest.build_opener()

        request = urlrequest.Request(strUrl)
        request.add_header('User-Agent', strUserAgent)
        request.add_header('Accept', "application/json")

        req = opener.open(request)
        strResponse = req.read().decode('utf8')

        return strResponse     
    except Exception as e:
        print("[-] Error on trying to get the response from ", strUrl, " ", str(e))
        return None

def checkMonth(strMonth, args, dtNow):
    strLastUpdate =     None
    jDoc =              None
    strUserAgent =      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    strBasePath =       args.basepath # "https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/"  # https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/2021-Aug
    if(args.month != None):
        strMonth = args.month

    if(args.useragent != None):
        strUserAgent = args.useragent 

    esConnection =      createElasticConnection(args)
    if(esConnection == None):
        print("[-] Warning: elasticsearch connection not defined hence nothing will be ingested")

    print("[+] Downloading ", strMonth, " ...")
    strFlaws = getMsFlaws(strBasePath + strMonth, strUserAgent, args.proxy)

    if(strFlaws == None):
        print("[-] Could not continue parsing non-existent json, returning")
        return

    jResponse = json.loads(strFlaws)
    

    if( 'CurrentReleaseDate' in jResponse['DocumentTracking']):
        print("Current Release Date: ", jResponse['DocumentTracking']['CurrentReleaseDate'])

        jDoc = getDocForMonth(strMonth)

        if(jDoc != None):
            strLastUpdate = jDoc['DocumentTracking']['CurrentReleaseDate']
            if(strLastUpdate == jResponse['DocumentTracking']['CurrentReleaseDate']):
                print("[+] Already ingested that version. ", strLastUpdate, " All done!")
                return

    # Ingest the changes to Elastic
    if ('Vulnerability' in jResponse):    

        # First, just log some debug info making sure that the json blob is correctly formatted
        for v in jResponse['Vulnerability']:
            strCVE = ""
            strTitle = ""

            if(v['CVE'] != None):
                strCVE = v['CVE']

            if(v['Title'] != None):
                if('Value' in v['Title']):
                    strTitle = v['Title']['Value']
                else:
                    strTitle = str(v['Title'])

            if(v['RevisionHistory'] != None):
            
                if(jDoc != None):                    
                    lastRevision = v['RevisionHistory'][len(v['RevisionHistory'])-1]   # Check the revisions. It assumes that the revisions are in order. TODO: maybe this is not always true?
                    strHistoryRevision = findRevision(jDoc, lastRevision, strCVE, strTitle)  # Assume that title + cve is unique. Otherwise we estimate it at least.

                    if(strHistoryRevision != lastRevision):
                        print("[+] New version. Should ingest ", strCVE, ".", strTitle)

                        if(esConnection != None):
                            ingestElasticsearch(esConnection, args.elasticindex, args.elastictimefield, v, dtNow, strCVE + "." + strTitle)
                else:
                    print("[+] No previous doc so just ingest ", strCVE, ".", strTitle)
                    if(esConnection != None):
                        ingestElasticsearch(esConnection, args.elasticindex, args.elastictimefield, v, dtNow, strCVE + "." + strTitle)                    

        # Write the history file
        writeDocForMonth(strMonth, jResponse)
    

def main():    
    # Parse arguments
    parser = argparse.ArgumentParser(description="If no argument is given, the latest month is ingested.")
    parser.add_argument("--month", help="Use this month", type=str)
    parser.add_argument("--proxy", help="Proxy to use", type=str)
    parser.add_argument("--start", help="If we should ingest from a specific month, then this is it. Example: 2021-Sep", type=str)
    parser.add_argument("--useragent", help="User agent to use for requests", type=str)
    parser.add_argument("--basepath", help="Use this path for microsoft cvrf", type=str, default="https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/")

    # Elastic output
    parser.add_argument("--elastichost", help="Use this elasticsearch host for output (default=127.0.0.1)", type=str)
    parser.add_argument("--elasticindex", help="Use this elasticsearch index for output. Example: msflaws-#yyyy#", type=str)
    parser.add_argument("--elasticuser", help="Use this elasticsearch user (if required by the elastic server)", type=str)
    parser.add_argument("--elasticpassword", help="Use this elasticsearch password (if required by the elastic server)", type=str)
    parser.add_argument("--elastictls", help="Use if elasticsearch requires https (more common these days)", action="store_true")
    parser.add_argument("--elasticskipcert", help="If specified no certificate validation occurs when connecting to elasticsearch (using this is NOT recommended of course)", action="store_true")
    parser.add_argument("--elasticport", help="If you have another port than 9200 for your elasticsearch then specify it here", type=int)
    parser.add_argument("--elastictimefield", help="Set the timefield for elasticsearch (default=@timestamp)", type=str)    
    args = parser.parse_args()    

    dtNow =             datetime.now()
    strMonth =          str(dtNow.year) + "-" + str(dtNow.strftime("%b"))    

    if(args.start != None):
        dtStart = datetime.strptime(args.start, '%Y-%b')
        dtEnd =  dtNow + relativedelta(months=+1)

        while(dtStart.month < dtEnd.month or dtStart.year < dtEnd.year):
            strMonth = str(dtStart.year) + "-" + str(dtStart.strftime("%b"))
            checkMonth(strMonth, args, dtNow)
            dtStart =  dtStart + relativedelta(months=+1)

    else:
        checkMonth(strMonth, args, dtNow)

    print("[+] Done!")

# Old fashioned python syntax
if __name__ == "__main__":    
    main()
