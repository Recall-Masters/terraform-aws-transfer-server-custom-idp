INCOMING_FOLDER = "incoming"
SFTP_COMPANY_PREFIX = "sftp/company="

DMS_FOLDERS = [
    "processed",
    "error",
]

DEALER_FOLDERS = [
    "Communication Plan",
    "Complete Reports",
    "Customer Sales Database",
    "Customer Service Database",
    "Mailed VINS",
    "Sales Transactions",
    "Service Transactions",
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
    "sftp/dms/": DMS_FOLDERS,
    "sftp/dealer=": DEALER_FOLDERS,
    SFTP_COMPANY_PREFIX: COMPANY_FOLDERS,
}
