# cert-extract-cmds
#
# definition file of assorted REST Commands for communicating
# with the source and destination servers
#
######################################################################
import  requests
from    urllib3.exceptions import InsecureRequestWarning
import  json
import  enum
import  re
from    cert_xtract_errors import *


# ---------------- CONSTANTS -----------------------------------------------------
STATUS_CODE_OK      = 200
STATUS_CODE_CREATED = 201
APP_JSON            = "application/json"

CM_REST_PREAMBLE    = "/api/v1/"


def makeHexStr(t_val):
# -------------------------------------------------------------------------------
# makeHexString
# -------------------------------------------------------------------------------
    tmpStr = str(t_val)
    t_hexStr = hex(int("0x" + tmpStr[2:-1], 0))

    return t_hexStr

def createCMAuthStr(t_cmHost, t_cmPort, t_cmUser, t_cmPass):
# -----------------------------------------------------------------------------
# REST Assembly for DESTINATION HOST LOGIN 
# 
# The objective of this section is to provide the username and password parameters
# to the REST interface of the CM host in return for a BEARER TOKEN that is 
# used for authentication of other commands.
# -----------------------------------------------------------------------------

    t_cmRESTAPI            = CM_REST_PREAMBLE + "auth/tokens/"
    t_cmHostRESTCmd        = "https://%s:%s%s" %(t_cmHost, t_cmPort, t_cmRESTAPI)  

    t_cmHeaders            = {"Content-Type":APP_JSON}
    t_cmBody               = {"name":t_cmUser, "password":t_cmPass}

    # Suppress SSL Verification Warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    # Note that CM does not required Basic Auth to retrieve information.  
    # Instead, the body of the call contains the username and password.
    r = requests.post(t_cmHostRESTCmd, data=json.dumps(t_cmBody), headers=t_cmHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        xPrintError("createCMAuthStr", r)
        exit()

    # Extract the Bearer Token from the value of the key-value pair of the JSON reponse which is identified by the 'jwt' key.
    t_cmUserBearerToken            = r.json()['jwt']
    t_cmAuthStr                    = "Bearer "+t_cmUserBearerToken

    return t_cmAuthStr

def getCMLocalCAs(t_cmHost, t_cmPort, t_cmAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for retrieving LOCAL CM CA Certificates
# 
# The objective of this section is to use the CM Authorization / Bearer Token
# to query the CM hosts REST interface about certificates.
# -----------------------------------------------------------------------------

    t_cmRESTAPI            = CM_REST_PREAMBLE + "ca/local-cas"
    t_cmHostRESTCmd        = "https://%s:%s%s" %(t_cmHost, t_cmPort, t_cmRESTAPI)   

    t_cmHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization": t_cmAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_cmHostRESTCmd, headers=t_cmHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        xPrintError("getCMObjList", r)
        exit()

    t_cmObjList           = r.json()['resources']

    # print("\n         CM Objects: ", t_cmObjList[0].keys())
    return t_cmObjList
    
def getCiphertext(t_cmHost, t_cmPort, t_cmAuthStr, t_cmBody):
# -----------------------------------------------------------------------------
# REST Assembly encrypting some data.
# -----------------------------------------------------------------------------

    t_cmRESTAPI            = CM_REST_PREAMBLE + "crypto/encrypt"
    t_cmHostRESTCmd        = "https://%s:%s%s" %(t_cmHost, t_cmPort, t_cmRESTAPI)   

    t_cmHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization": t_cmAuthStr}

    r = requests.post(t_cmHostRESTCmd, data=json.dumps(t_cmBody), headers=t_cmHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        xPrintError("getCiphertext", r)
        exit()

    t_cmResult           = r.json()['ciphertext']

    # print("\n         CM Objects: ", t_cmObjList[0].keys())
    return t_cmResult

def getClientInfo(t_cmHost, t_cmPort, t_cmAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for getting a list of registered clients.
# -----------------------------------------------------------------------------

    t_cmRESTAPI            = CM_REST_PREAMBLE + "transparent-encryption/clients"
    t_cmHostRESTCmd        = "https://%s:%s%s" %(t_cmHost, t_cmPort, t_cmRESTAPI)   

    t_cmHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization": t_cmAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_cmHostRESTCmd, headers=t_cmHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        xPrintError("getClientInfo", r)
        exit()

    t_cmResult           = r.json()['resources']

    # print("\n         CM Objects: ", t_cmObjList[0].keys())
    return t_cmResult