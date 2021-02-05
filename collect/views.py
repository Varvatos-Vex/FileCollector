from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import pandas as pd
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
                dataframe = pd.read_csv(io.StringIO(uploaded_file.read().decode('utf-8')), delimiter=',')
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
        if dataframe.isna():
           print("Null Value Error")
        else:
            Print("Null Ok")

    except Exception as e:
        print("Blanks Available")
        FileError = 'Remove Blanks'
        print(e)
        pass
    

