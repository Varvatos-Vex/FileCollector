from django.shortcuts import render, redirect 
from django.http import HttpResponse
import pandas as pd
import datetime
from django.views.decorators.csrf import csrf_exempt,csrf_protect
import io

from pandas.core.frame import DataFrame
from .models import FileDetails
from datetime import timedelta  

final_tpi = pd.DataFrame()
final_tpiCombine = pd.DataFrame()


def tpi_ipFunc(df_ip):
    x = datetime.datetime.now()
    Firstdate = x.strftime('%d/%m/%Y')
    try:
        df_ip = df_ip[df_ip.VT_Detection.astype('Int64') >= 1]
    except:
        pass
    global final_tpi
    df_ip = df_ip[['IOCDetails','Country','DateofInput','VT_Detection','IOCType']]
    #df_ip = df_ip.rename(columns={"DateofInput": "FirstSeen"})
    df_ip = df_ip.assign(FirstSeen = Firstdate)
    df_ip = df_ip.assign(LastSeen = Firstdate)
    #df_ip['LastSeen'] = df_ip['FirstSeen']
    final_tpi = df_ip[['IOCDetails','Country','FirstSeen','LastSeen','VT_Detection','IOCType']]

from pytz import timezone
from dateutil import parser
def tpi_domainFunc(df_domain):
    x = datetime.datetime.now()
    Firstdate = x.strftime('%d/%m/%Y')
    global final_tpi
    tpi_domain = df_domain[['IOCDetails','VT_Detection','IOCType']]
    tpi_domain = tpi_domain.assign(Country = 'NA')
    tpi_domain = tpi_domain.assign(FirstSeen = Firstdate)
    tpi_domain = tpi_domain.assign(LastSeen = Firstdate)
    domainExtractedIp = DataFrame()
    if not final_tpi.empty:
        domainExtractedIp = df_domain[~(df_domain['ViolationIP'].isin(final_tpi['IOCDetails']))].reset_index(drop=True) #-----domain Ip not available in direct IP. link -> https://stackoverflow.com/questions/48647534/python-pandas-find-difference-between-two-data-frames

    if not domainExtractedIp.empty:
        try:    
            domainExtractedIp = domainExtractedIp[domainExtractedIp.VT_Detection.astype('Int64') >= 5]
        except Exception as e:
            print(e)
            pass
        backDate5Month = parser.parse(Firstdate) - timedelta(days = 60)
        backDate5Month = backDate5Month.strftime('%d/%m/%Y')
        domainExtractedIp = domainExtractedIp[['ViolationIP','Country','VT_Detection','IOCType']]
        domainExtractedIp = domainExtractedIp.assign(FirstSeen = backDate5Month)
        domainExtractedIp = domainExtractedIp.assign(LastSeen = Firstdate)
        domainExtractedIp = domainExtractedIp.rename(columns={"ViolationIP": "IOCDetails"})
        tpi_domain = tpi_domain.append(domainExtractedIp)
    final_tpi = final_tpi.append(tpi_domain)

def tpi_HashFunc(df_hash):
    global final_tpi
    x = datetime.datetime.now()
    Firstdate = x.strftime('%d/%m/%Y')
    backDate5Month = parser.parse(Firstdate) - timedelta(days = 60)
    backDate5Month = backDate5Month.strftime('%d/%m/%Y')
    #df_hash = df_hash.loc[df_hash['ViolationIP'] != 'NA']
    HashExtractedIp = DataFrame()
    if not final_tpi.empty:
        HashExtractedIp = df_hash[~(df_hash['ViolationIP'].isin(final_tpi['IOCDetails']))].reset_index(drop=True)
    if not HashExtractedIp.empty:
        #HashExtractedIp.dropna(subset=['VT_Detection'])
        HashExtractedIp['VT_Detection'].fillna(0)
        try:
            HashExtractedIp = HashExtractedIp[HashExtractedIp.VT_Detection.astype('Int64') >= 5]
        except Exception as e:
            print(e)
            pass
        HashExtractedIp = HashExtractedIp[['ViolationIP','Country','VT_Detection','IOCType']]
        HashExtractedIp = HashExtractedIp.assign(FirstSeen = backDate5Month)
        HashExtractedIp = HashExtractedIp.assign(LastSeen = Firstdate)
        HashExtractedIp = HashExtractedIp.rename(columns={"ViolationIP": "IOCDetails"})
        final_tpi = final_tpi.append(HashExtractedIp)
    

#---------------- Program Start Here---------------
def creatTpi(df):
    global final_tpi
    global final_tpiCombine
    x = datetime.datetime.now()
    Firstdate = x.strftime('%d/%m/%Y')
    count = 1
    sourceOfIoc = df['SourceofIOC'].iloc[0]
    sourceOfIoc = 'TA_' + sourceOfIoc
    Remark = df['ThreatActor'].iloc[0]
    Risk = df['Type'].iloc[0] + '/' + df['IntentofThreatActor'].iloc[0]

    df_ip = df.loc[(df.IOCType == 'IP') & (df['ViolationIP'].notnull())] #-------------------Extract Direct IP List
    df_domain = df.loc[(df.IOCType == 'Domain') & (df['ViolationIP'].notnull())] #-------------------Extract Domain  List
    df_hash = df.loc[(df['IOCType'] != 'IP') & (df['IOCType'] != 'Domain') & (df['ViolationIP'].notnull())] #-------------------Extract Hash  List

    if not df_ip.empty:
        tpi_ipFunc(df_ip)
    if not df_domain.empty:
        tpi_domainFunc(df_domain)
    if not df_hash.empty:
        tpi_HashFunc(df_hash)
    #final_tpi = final_tpi.assign(Firstdate = Firstdate)
    #final_tpi = final_tpi.assign(Lastdate = Firstdate)
    final_tpi = final_tpi.assign(sourceOfIoc = sourceOfIoc)
    final_tpi = final_tpi.assign(Remark = Remark)
    final_tpi = final_tpi.assign(Risk = Risk)
    final_tpi = final_tpi.assign(Count = '1')
    final_tpiCombine = final_tpiCombine.append(final_tpi)
    final_tpi = pd.DataFrame()

#final_tpi.to_csv('FinalTpi.csv',header=True,columns=["Firstdate","Lastdate","IOCDetails","Country","sourceOfIoc","Remark","Risk"])
def tpi(request):
    f = open("media/TPIcheckpoint.txt", "r")
    checkpoint = f.read()
    return render(request, 'dashboard/tpi.html',context=({"data":checkpoint}))

@csrf_exempt    
def tpi_res1(request):
    global final_tpi
    if request.method == 'POST':
        try:
            uploaded_file = request.FILES.get('file_data')
            if (uploaded_file is not None):
                dataframe = pd.read_csv(io.StringIO(uploaded_file.read().decode('utf-8')), delimiter=',')
                #print(dataframe)


                creatTpi(dataframe)
                final_tpi = final_tpi.drop_duplicates()

                response = HttpResponse(content_type='text/csv')
                response['Content-Disposition'] = 'attachment; filename=filename.csv'
                final_tpi.to_csv(response,sep=',',float_format='%.2f',index=False,decimal=",",header=True,columns=["FirstSeen","LastSeen","IOCDetails","Country","sourceOfIoc","Count","Remark","Risk",'VT_Detection','IOCType'])

                #return HttpResponse(request.POST.get('daterange1'))
                return response


            else:
                return HttpResponse("File not Found")
        except  Exception as e:
            print(e)
            return HttpResponse("Wrong File")
    else:
        return HttpResponse("Failed")





@csrf_exempt    
def tpi_res(request):
    global final_tpiCombine
    reqCheck = request.POST.get('file_data')
    if reqCheck is None:
        f = open("media/TPIcheckpoint.txt", "r")
        checkpoint = f.read()
    else:
        checkpoint = reqCheck
    print(checkpoint)
    #return HttpResponse('Failed')
    now = datetime.datetime.now()
    data = FileDetails.objects.filter(date__range=[checkpoint, now],Index = 'Datalake_TA') #Filter Between Date Range and Index = Datalake_TA
    FilepathList = []
    for dt in data:
        FilepathList.append(dt.FilePath)
    if not FilepathList:
        combined_csv =  pd.DataFrame()
    else:
        for f1 in FilepathList:
            temp = pd.read_csv(f1)
            creatTpi(temp)
    
    final_tpiCombine = final_tpiCombine.drop_duplicates()
    final_tpiCombine = final_tpiCombine.drop_duplicates(subset=["FirstSeen","LastSeen","IOCDetails","Country","sourceOfIoc","Count","Remark","Risk"])
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename=filename.csv'
    try:
        final_tpiCombine.to_csv(response,sep=',',float_format='%.2f',index=False,decimal=",",header=True,columns=["FirstSeen","LastSeen","IOCDetails","Country","sourceOfIoc","Count","Remark","Risk",'VT_Detection','IOCType'])
    except:
        return HttpResponse("Not Available")
    #return HttpResponse(request.POST.get('daterange1'))
    f = open("media/TPIcheckpoint.txt", "w")
    f.write(str(now))
    f.close()
    final_tpiCombine = DataFrame()
    return response
