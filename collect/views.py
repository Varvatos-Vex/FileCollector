from django.shortcuts import render, redirect 
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt,csrf_protect
import pandas as pd
import numpy as np
import io
import time
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout, authenticate, login
from django.contrib import messages


FileError = ''

@csrf_exempt
@login_required(login_url='index')
def index(request):
    return render(request, 'index.html')


@csrf_exempt
def Login(request):
    if request.user.is_authenticated:
        return render(request, 'index.html')
    else:
        if request.method == 'POST':
            username = request.POST.get('username')
            password =request.POST.get('password')
            user = authenticate(request,username = username, password = password)
            if user is not None:
                login(request, user)
                return render(request, 'index.html')
            else:
                return render(request, 'login.html')
        return render(request, 'login.html')



def Logout(request):
    logout(request)
    return redirect('login')


@csrf_exempt
def ValidateFile(request):
    global FileError
    FileError = 'success'
    if request.method == 'POST':
            uploaded_file = request.FILES.get('file_data')
            if uploaded_file is not None:
                dataframe = pd.read_csv(io.StringIO(uploaded_file.read().decode('utf-8')), delimiter=',',keep_default_na=False,na_values = "")
                #print(dataframe)
                ThreatActor = dataframe['ThreatActor']
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
        time.sleep(5)
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
    

