from django.shortcuts import render, redirect 
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt,csrf_protect
from .models import MispGalaxies, AVModel, TActorModel
import pandas as pd
import io
from pytz import timezone
import requests 
import json
import re
import datetime
import sys
import unidecode
from datetime import date
import csv


def otx(request):
    LastAVFile = AVModel.objects.all().order_by('-id')[:10]
    return render(request, 'dashboard/otxAV.html',{"avFileData":LastAVFile})

@csrf_exempt
def fetchOtx(request):
    try:
        try:
            obj = AVModel.objects.last()
            lastDate = getattr(obj, 'date')
            lastDate = lastDate.astimezone(timezone('Asia/Kolkata'))
        except Exception as e:
            print(e)
            lastDate = '2021-03-15 09:55:37.983857'

        now=str(datetime.datetime.now())
        
        otxAPICall(now,lastDate)

        return HttpResponse("Success")
    except:
        return HttpResponse("Failed")
        


def otxAPICall(now,lastDate):
    lastDate = str(lastDate)
    api_key="69ff2a75d26791c2e230e9ef496b36f15022c105f2b4033f1af7e261fe380b8b"
    response=requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=5000&modified_since="+lastDate.strip(),headers={"X-OTX-API-KEY":api_key})
    jdata=json.loads(response.text)
    falesh_finalData = []
    lnum = 0
    for p in jdata["results"]:
        date = ""
        if "created" in p:
            date = unidecode.unidecode(str(p["created"]))[:10]
            mon = date[5:7]
            datetime_object = datetime.datetime.strptime(mon, "%m")
            month_name = datetime_object.strftime("%B")

        pulse_id = ""
        if "id" in p:
            pulse_id = "https://otx.alienvault.com/pulse/"+p["id"]
            print("Processed pulse Id - "+pulse_id+"\n")

        
        Type=""
        name=""
        if "name" in p:
            name = p['name']
            '''ThreatActorName =  Threatmap.Threatmap.threatActor(name)
            ThreatActorGroup = ThreatActorName[0]
            ThreatActorCountry = ThreatActorName[1]
            Type = "APT"
            if(ThreatActorGroup == 'Unknown'):
                ThreatActorGroup = name
                Type = "Malware"'''
            ThreatActorGroup = name
            Type = 'Malware'
            ThreatActorCountry = 'Unknown'
        
        author=""
        
        if "author_name" in p:
            author=p["author_name"]

        tags = ""

        if "tags" in p:
            tags=p["tags"]

        if "indicators" in p:

            for r in p["indicators"]:
                if(r['type'] == 'FileHash-MD5'
                 or r['type'] == 'FileHash-SHA256'
                 or r['type'] == 'IPv4'
                 or r['type'] == 'FileHash-SHA1'
                 or r['type'] == 'domain' 
                 or r['type'] == 'URL' 
                 or r['type'] == 'hostname'):

                    if(r['type']=='FileHash-MD5'):
                        ioc_type = 'MD5'
                    elif(r['type']=='FileHash-SHA256'):
                        ioc_type = 'SHA256'
                    elif(r['type']=='FileHash-SHA1'):
                        ioc_type = 'SHA1'
                    elif(r['type']=='IPv4'):
                        ioc_type = 'IP' 
                    elif(r['type']=='domain' or r['type']=='hostname'):
                        ioc_type = 'HOST'   
                    elif(r['type']=='URL'):
                        ioc_type = 'URL'    

                    tmp_dict={}
                    tmp_dict['ioc_type'] = ioc_type
                    tmp_dict['indicator'] = r['indicator']
                    tmp_dict['date'] = date
                    tmp_dict['ThreatActorGroup'] = ThreatActorGroup
                    tmp_dict['month_name'] = month_name
                    tmp_dict['tags'] = tags
                    tmp_dict['name'] = name
                    tmp_dict['ThreatActorCountry'] = ThreatActorCountry
                    tmp_dict['Type'] = Type
                    tmp_dict['pulse_id'] = pulse_id
                    lnum = lnum + 1
                    falesh_finalData.append(tmp_dict)
        else:
            print("indicators not found")
    print(lnum)
    if lnum != 0:
        filename = "/home/user/Documents/FileCollector/media/AV/" + now + ".csv"
        csv_header = ["Team","SourceofIOC","Month","DateofInput","ThreatActor","SuspectedAttribution","Type","IntentofThreatActor","IOCDetails","OriginalPulseName","Tag","IOCType","Remarks"]
        file = open(filename, mode='w+')
        writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(csv_header)
        for row in falesh_finalData:
            #print(row)
            writer.writerow([
                "TA",
                "ALIENVAULT",
                row['month_name'],
                row['date'],
                row['ThreatActorGroup'],
                row['ThreatActorCountry'],
                row['Type'],
                row['Type'],
                row['indicator'],
                row['name'],
                row['tags'],
                row['ioc_type'],
                row['pulse_id']
                ])
        filePath = 'AV/' + str(now) + '.csv'
        ob = AVModel(FilePath= filePath)
        ob.save()

    else:
        print("No IOCs are downloaded")


      

#--------------------------------Upadte MISP Data--------------------------------
def misp(request):
    return render(request, 'dashboard/misp.html')


@csrf_exempt
def misp_res(request):
    if request.method == 'POST':
        try:
            uploaded_file = request.FILES.get('file_data')
            if (uploaded_file is not None):
                dataframe = pd.read_csv(io.StringIO(uploaded_file.read().decode('utf-8')), delimiter=',')

                ingestMisp(dataframe)

                return HttpResponse("Success")
            else:
                return HttpResponse("File not Found")
        except  Exception as e:
            print(e)
            return HttpResponse("Wrong File {}".format(e))
    else:
        return HttpResponse("Failed")


def ingestMisp(dataframe):
    MispGalaxies.objects.all().delete() #First Delete ALl data and then Ingest
    MispGalaxies.objects.bulk_create(
        MispGalaxies(**vals)  for vals in dataframe.to_dict('records')
    )
    pass



#--------------------------------Upadte ThreatActor Data--------------------------------
def tactor(request):
    return render(request, 'dashboard/tactor.html')


@csrf_exempt
def tactor_res(request):
    if request.method == 'POST':
        try:
            uploaded_file = request.FILES.get('file_data')
            if (uploaded_file is not None):
                dataframe = pd.read_csv(io.StringIO(uploaded_file.read().decode('utf-8')), delimiter=':')
                '''dataframe = dataframe[['Name', 'OtherNames']]
                print(dataframe)'''
                ingestTActor(dataframe)

                return HttpResponse("Success")
            else:
                return HttpResponse("File not Found")
        except  Exception as e:
            print(e)
            return HttpResponse("Wrong File {}".format(e))
    else:
        return HttpResponse("Failed")


def ingestTActor(dataframe):
    TActorModel.objects.all().delete() #First Delete ALl data and then Ingest
    TActorModel.objects.bulk_create(
        TActorModel(**vals)  for vals in dataframe.to_dict('records')
    )
    pass


def TactorResponse(request):
    rq = request.GET.get('q', None)
    if rq is not None and rq !='':
        rq = rq.strip()
        return HttpResponse(rq)
    else:
        return HttpResponse("Null Value")