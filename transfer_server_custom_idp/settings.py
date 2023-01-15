INCOMING_FOLDER = "incoming"
SFTP_COMPANY_PREFIX_REGEX = "^.*(sftp/dealer=|sftp/company=).*$"
SFTP_COMPANY_TYPE_SUFFIX_REGEX = "^.*(/type=vin/|/type=inventory/).*$"
DMS_FOLDERS = [
    "processed",
    "error",
]

DEALER_FOLDERS = [
    "Communication_Plan",
    "Complete_Reports",
    "Customer_Sales_Database",
    "Customer_Service_Database",
    "Mailed_VINS",
    "Sales_Transactions",
    "Service_Transactions",
]


COMPANY_FOLDERS = [
    "processing",
    "outgoing",
    "error",
    "incoming_repaired",
    "incoming_repaired/incoming",
    "incoming_repaired/error",
    "incoming_repaired/processing",
    "incoming_repaired/outgoing",
]

HOME_DIRECTORY_TO_FOLDERS_MAPPING = {
    "^(/type=dms/).*$": DMS_FOLDERS,
    "^(?!.*(/type=)).*(sftp/dealer=|sftp/company=).*$": DEALER_FOLDERS,
}

AWS_REGION = "us-west-2"
