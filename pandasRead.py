import pandas as pd
import numpy as np

from datetime import datetime
from dateutil import parser


dataframe = pd.read_csv('/home/user/Documents/FileCollector/TeamTNT_ta.csv', delimiter=',',keep_default_na=False,na_values = "")
try:
    pd.to_datetime(dataframe['DateofInput'], format='%Y-%m-%d', errors='raise')
    print("No Error")
    dateList = dataframe['DateofInput'].tolist()
    print(dateList)
except ValueError:
    print("Date Validation Failed")


exit(1)

#----------------------To Strip every cell in CSV---------------------------

tmp = "January 26, 2021"
print(parser.parse(tmp))
#print(datetime.strptime(tmp, '%B %m, %Y'))



dataframe = pd.read_csv('/home/user/Documents/FileCollector/TeamTNT_ta.csv', delimiter=',',keep_default_na=False,na_values = "")


print(dataframe['ThreatActor'].iloc[0])


#----------------------To Strip every cell in CSV---------------------------
df = dataframe.apply(lambda x: x.str.strip() if x.dtype == "object" else x)
df.to_csv(r'out.csv', index = False)
df.to_json()


#----------------------Compare Columns in CSV---------------------------
indx1 = dataframe.columns.tolist()

indx2 = ['Team', 'SourceofIOC', 'NameofAnalyst', 'Month', 'DateofInput', 'ThreatActor', 'SuspectedAttribution', 'Type', 'IntentofThreatActor', 'IOCDetails', 'DerivedIOC', 'DerivedType', 'ViolationIP', 'VT_Detection', 'AbuseIpDB', 'TPI', 'Country', 'NameofOrganistion', 'UsageType', 'FirstSeen', 'Violation_Date', 'LastSeen', 'DetectBetweenFirstLastSeen', 'CII', 'Sectors', 'ConnectionType', 'ViolationPort', 'Status', 'OriginalPulseName', 'Tag', 'Aliases', 'IOCType', 'Remarks']

if (indx1 == indx2):
    print("True")
else:
    print("False")
