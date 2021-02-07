import pandas as pd
import numpy as np


dataframe = pd.read_csv('/home/joker/Downloads/TeamTNT_ta.csv', delimiter=',',keep_default_na=False,na_values = "")
CountNan = str(dataframe.isnull().values.any())

print(CountNan)
'''if(dataframe.isnull().sum()):
    print("Empty")
else:
    print("Not Empty")'''
