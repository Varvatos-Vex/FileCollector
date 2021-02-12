from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import pandas as pd
import numpy as np
import io
FileError = ''

def index(request):
    return render(request, 'index.html')


@csrf_exempt
def ValidateFile(request):
    global FileError
    FileError = 'success'
    if request.method == 'POST':
            uploaded_file = request.FILES.get('file_data')
            if uploaded_file is not None:
                dataframe = pd.read_csv(io.StringIO(uploaded_file.read().decode('utf-8')), delimiter=',',keep_default_na=False,na_values = "")
                #print(dataframe)

                validating(dataframe)





                return HttpResponse(FileError)
            else:
                return HttpResponse("File not Found")
    else:
        return HttpResponse("Failed")


def validating(dataframe):
    global FileError

    #-----------------------DateofInput Column Validate---------------------------------
    try:
        pd.to_datetime(dataframe['DateofInput'], format='%Y-%m-%d', errors='raise')
        print("Date Validation Ok")
    except ValueError:
        print("Date Validation Failed")
        FileError = 'Date Validation Failed'
        pass
   
    #-----------------------Null Value Validate---------------------------------
    try:
        if (dataframe.isnull().values.any()):
            FileError = 'Remove Blanks'
        else:
            print("No blanks")

    except Exception as e:
        FileError = 'Remove Blanks'
        print(e)
        pass

    #-----------------------Trim every cell---------------------------------
    try:
        dataframe = dataframe.apply(lambda x: x.str.strip() if x.dtype == "object" else x)
    except Exception as e:
        FileError = 'Trim Error'
        print(e)
        pass
    

