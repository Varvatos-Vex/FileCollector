from django.shortcuts import render, redirect 
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt,csrf_protect
import pandas as pd
import numpy as np
import io
import time
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout, authenticate, login
from django.contrib import messages
from .models import FileDetails, AliasTable, SourceTable, ThreatActorTable, MispGalaxies
from django.core import serializers

FileError = ''

@csrf_exempt
@login_required(login_url='login')
def index(request):
    return render(request, 'index.html')


@csrf_exempt
def Login(request):
    if request.user.is_authenticated:
        return render(request, 'dashboard/home.html')
    else:
        if request.method == 'POST':
            username = request.POST.get('username')
            password =request.POST.get('password')
            user = authenticate(request,username = username, password = password)
            if user is not None:
                login(request, user)
                return render(request, 'dashboard/home.html')
            else:
                return render(request, 'login.html')
        return render(request, 'login.html')



def Logout(request):
    logout(request)
    return redirect('login')

from django.contrib.auth.models import User

@csrf_exempt
@login_required
def changePass(request):
    uname = request.user.username
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        retype_new_password = request.POST.get('retype_new_password')
        if request.user.is_authenticated:
            if new_password == retype_new_password and new_password != '':
                u = User.objects.get(username=uname)
                u.set_password(new_password)
                u.save()
                message = 'Successfully Changed the Password.'
            else:
                message = 'Invalid Passwords!'
        else:
            message = 'Invalid Password!'
    return HttpResponse(json.dumps(message), content_type='application/json')



@csrf_exempt
def ValidateFile(request):
    global FileError
    FileError = 'success'
    if request.method == 'POST':
        try:
            uploaded_file = request.FILES.get('file_data')
            definition = request.POST.get('definition')
            if (uploaded_file is not None) and (len(definition) != 0):
                dataframe = pd.read_csv(io.StringIO(uploaded_file.read().decode('utf-8')), delimiter=',',keep_default_na=False,na_values = "")
                #print(dataframe)
                ThreatActor = dataframe['ThreatActor'].iloc[0]
                user = request.user
                Index = CheckIndex(dataframe) #----------Function Check the Index by comaparing their headers
                validating(dataframe)
                
                #validateActor(dataframe,ThreatActor)
                if (FileError == 'success'):
                    ob = FileDetails(User = user, Index= Index, ThreatActor=ThreatActor,FilePath= uploaded_file, Defination = definition)
                    ob.save()
                    return HttpResponse(FileError)
                    
                else:
                    return HttpResponse(FileError)
            else:
                return HttpResponse("File not Found or Empty Definition")
        except  Exception as e:
            print(e)
            return HttpResponse("Wrong File {}".format(e))
    else:
        return HttpResponse("Failed")


#-----------This fuction check Date of Input, Null Value, and Remove Blanks
def validating(dataframe):
    global FileError

    #-----------------------DateofInput Column Validate---------------------------------
    try:
        pd.to_datetime(dataframe['DateofInput'], format='%Y-%m-%d', errors='raise',exact=True)
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


#-----------This fuction check Threat Actor AVailable------------
def validateActor(dataframe,ThreatActor):
    global FileError
    if not ThreatActorTable.objects.all().filter(ThreatActor = ThreatActor).count():
        FileError = 'No Actors Found Please Add'
    if len(pd.unique(dataframe['ThreatActor'])) > 1 :
        FileError = 'Multiple Threat Actor'


def validateSource(dataframe,ThreatActor):
    global FileError
    if not ThreatActorTable.objects.all().filter(ThreatActor = ThreatActor).count():
        FileError = 'ThreatActorNot Please Add'





 #---------------Check The Index Of Uploaded CSV FILE---------------------   
def CheckIndex(dataframe):
    global FileError
    indx1 = dataframe.columns.tolist() #----main DataFrame File

    indx2 = ['Team', 'SourceofIOC', 'NameofAnalyst', 'Month', 'DateofInput', 'ThreatActor', 'SuspectedAttribution', 'Type', 'IntentofThreatActor', 'IOCDetails', 'DerivedIOC', 'DerivedType', 'ViolationIP', 'VT_Detection', 'AbuseIpDB', 'TPI', 'Country', 'NameofOrganistion', 'UsageType', 'FirstSeen', 'Violation_Date', 'LastSeen', 'DetectBetweenFirstLastSeen', 'CII', 'Sectors', 'ConnectionType', 'ViolationPort', 'Status', 'OriginalPulseName', 'Tag', 'Aliases', 'IOCType', 'Remarks']
    indx3 = ['Team','SourceofIOC','Month','DateofInput','ThreatActor','SuspectedAttribution','Type','IntentofThreatActor','IOCDetails','OriginalPulseName','Tag','IOCType','Remarks']
    if (indx1 == indx2):
        return "Datalake_TA"
    elif(indx1 == indx3):
        return "Datalake"
    else:
        FileError = 'Wrong Header'

@login_required(login_url='login')
def dashboard(request):
    FileData = FileDetails.objects.all().filter(User= request.user ).order_by('-id')[:50]
    return render(request, 'dashboard/home.html',{"FileData":FileData})


@login_required(login_url='login')
def home(request):
    user = request.user
    FileData = FileDetails.objects.all().filter(User= request.user ).order_by('-id')[:50]
    return render(request, "dashboard/home.html",{"FileData":FileData})

#--------------------------------------Fetch Data for DataTable in Threat Actor Section--------------------------
@login_required(login_url='login')
def threat(request):
    ThreatActor = MispGalaxies.objects.all().order_by('ThreatActor')
    return render(request, "dashboard/threatactor.html",{"data": ThreatActor})

@csrf_exempt
def thretadetails(request):
    if request.method == 'POST':
        uuid = request.POST.get('uuid')
        ThreatActor = MispGalaxies.objects.filter(uuid = uuid)
        ThreatActor = serializers.serialize('json', ThreatActor)
        return JsonResponse(ThreatActor, safe=False)
    else:
        return HttpResponse("Failed")


#--------------------------------------Auto Complete Search Box in Threat Actor Section--------------------------
import json
from django.db.models import Q
@login_required(login_url='login')
def autocompleteModel(request):
    if request.is_ajax():
        q = request.GET.get('term', '').capitalize()
        #search_qs = ThreatActorTable.objects.filter(ThreatActor__icontains=q)
        search_qs = MispGalaxies.objects.filter(Q(Alias__icontains=q) | Q(ThreatActor__icontains=q))
        #qs_json = serializers.serialize('json', search_qs)
        results = []
        for r in search_qs:
            results.append(r.ThreatActor)
        print(results)
        data = json.dumps(results)

    else:
        data = 'fail'
    mimetype = 'application/json'
    return HttpResponse(data, mimetype)


#--------------The Below 2 Funtion Export the consolidated Output ---------------------- 
@login_required(login_url='login')
def report(request):
    return render(request, "dashboard/report.html")

import os
from dateutil import parser
from datetime import datetime  
from datetime import timedelta  
from pytz import timezone
@csrf_exempt
@login_required(login_url='login')
def daterange(request):
    daterange = request.POST.get('daterange1')
    index = request.POST.get('index')
    tmp = daterange.split(" - ")
    start = parser.parse(tmp[0]).astimezone(timezone('Asia/Kolkata'))
    end = parser.parse(tmp[1]).astimezone(timezone('Asia/Kolkata'))  + timedelta(days=1)
    print(start)
    print(end)

    data = FileDetails.objects.filter(date__range=[start, end],Index = index) #Filter Between Date Range and Index = Datalake_TA
    FilepathList = []
    for dt in data:
        FilepathList.append(dt.FilePath)
    if not FilepathList:
        combined_csv =  pd.DataFrame()
    else:
        combined_csv = pd.concat([pd.read_csv(f,keep_default_na=False,) for f in FilepathList ]) #Combile All data into single frame using file Path
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename=filename.csv'
    combined_csv.to_csv(response,sep=',',float_format='%.2f',index=False,decimal=",")

    #return HttpResponse(request.POST.get('daterange1'))
    return response

