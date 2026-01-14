#####################################################################################
#
# 	Name: cert-xtract.py
# 	Author: Rick R
# 	Purpose:  Python-based REST CA certificate extractor Transfer
#   Usage: py cert-xtract.py -srcHost <hostname or IP> -srcUser <username> -srcPass <password>                     
#                   
#####################################################################################

import  argparse
import  binascii
import  codecs
import  hashlib
from    cert_xtract_errors import *
from    cert_xtract_cmds import *

# ---------------- Constants ----------------------------------------------------
DEFAULT_SRC_PORT    = ["443"]

# ################################################################################

# ----- INPUT PARSING BEGIN ------------------------------------------------------

# Parse command.  Note that if the arguments are not complete, a usage message 
# will be printed automatically
parser = argparse.ArgumentParser(prog="cert-xtract.py", description="REST-based CA Certificate Extractor for CipherTrust Manager")

# Src Information
parser.add_argument("-srcHost", nargs=1, action="store", dest="srcHost", required=True)
parser.add_argument("-srcPort", nargs=1, action="store", dest="srcPort", default=DEFAULT_SRC_PORT)
parser.add_argument("-srcUser", nargs=1, action="store", dest="srcUser", required=True)
parser.add_argument("-srcPass", nargs=1, action="store", dest="srcPass", required=True)

####################################################################################
# NOTE: The following OPTIONAL flags are commulative, meaning that only keys that satisfy ALL
# of the UUID and NetApp flags will be processed.
####################################################################################

# Args are returned as a LIST.  Separate them into individual strings
args = parser.parse_args()

# Display results from inputs
print("\n ---- CIPHERTRUST PARAMETERS ----")

srcHost = str(" ".join(args.srcHost))
srcPort = str(" ".join(args.srcPort))
srcUser = str(" ".join(args.srcUser))
srcPass = str(" ".join(args.srcPass))
tmpStr = " SrcHost: %s\n SrcPort: %s\n SrcUser: %s\n" %(srcHost, srcPort, srcUser)
print(tmpStr)

# ################################################################################
# ---- MAIN MAIN MAIN ------------------------------------------------------------
# ################################################################################

# --------- Retrieve Certs --------------------------

# Get Source and Destination Authorization Token/Strings
print("\n Accessing Source and collecting Authorization Strings...")

srcAuthStr      = createCMAuthStr(srcHost, srcPort, srcUser, srcPass)
print("  * Source Access Confirmed *")
tmpStr = "    Username: %s\n" %(srcUser)
print(tmpStr)
    
# Get list of CA Certificates from source
print("\n --- Let's get the local CAs... ---\n")

srcCertList      = getCMLocalCAs(srcHost, srcPort, srcAuthStr)
srcCertListCnt   = len(srcCertList)

print("Number of CA Certificates: ", srcCertListCnt)

print("\nCA Certificates\n")

for cert in srcCertList:
    print("Subject: %s\n  Issuer: %s\n" %(cert['subject'], cert['issuer']) )

# --------- Encrypt Something --------------------------
print("\n --- Let's try some Encryption... ---\n")

t_plaintext = "Robinson"

jsonPlaintext   = {
    "id": "Alice-Eng-Key",
    "plaintext": t_plaintext,
    "mode": "CBC",
    "iv": "Cd7m6CWhC389DDVtJmW4bw=="
    }

jsonCiphertext  = getCiphertext(srcHost, srcPort, srcAuthStr, jsonPlaintext)
    
print("Plaintext: %s\nCiphertext: %s" %(t_plaintext, jsonCiphertext))


# --------- Check Client Health --------------------------
print("\n --- Let's check client health... ---\n")

jsonClients  = getClientInfo(srcHost, srcPort, srcAuthStr)

# print("\n jsonClients: ", json.dumps(jsonClients, skipkeys = True, allow_nan = True, indent = 3))

for client in jsonClients:
    print("Client Name:", client["name"])
    print("Client Description:", client["description"])
    print("Client OS:", client["os_type"], client["os_sub_type"], client["os_kernel"])
    print("Client Version:", client["client_version"])
    print("Client Status:", client["client_health_status"])

#####################################################################################
#
