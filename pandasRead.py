import pandas as pd
import numpy as np


dataframe = pd.read_csv('/home/user/Documents/FileCollector/TeamTNT_ta.csv', delimiter=',',keep_default_na=False,na_values = "")


ThreatActor = dataframe['ThreatActor']
print(ThreatActor)



exit(1)


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
