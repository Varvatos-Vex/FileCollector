from django.shortcuts import render, redirect 
from django.http import HttpResponse
import pandas as pd
import datetime
from django.views.decorators.csrf import csrf_exempt,csrf_protect
import io


final_tpi = pd.DataFrame()


def tpi_ipFunc(df_ip):
    try:
        df_ip = df_ip[df_ip.VT_Detection.astype(int) >= 0]
    except:
        pass
    global final_tpi
    final_tpi = df_ip[['IOCDetails','Country']]



def tpi_domainFunc(df_domain):
    global final_tpi
    tpi_domain = df_domain[['IOCDetails']]
    tpi_domain = tpi_domain.assign(Country = 'NA')
    domainExtractedIp = df_domain[~(df_domain['ViolationIP'].isin(final_tpi['IOCDetails']))].reset_index(drop=True) #-----domain Ip not available in direct IP. link -> https://stackoverflow.com/questions/48647534/python-pandas-find-difference-between-two-data-frames
    try:    
        domainExtractedIp = domainExtractedIp[domainExtractedIp.VT_Detection.astype(int) >= 5]
    except:
        pass
    domainExtractedIp = domainExtractedIp[['ViolationIP','Country']]
    domainExtractedIp = domainExtractedIp.rename(columns={"ViolationIP": "IOCDetails"})
    tpi_domain = tpi_domain.append(domainExtractedIp)
    final_tpi = final_tpi.append(tpi_domain)

def tpi_HashFunc(df_hash):
    global final_tpi
    #df_hash = df_hash.loc[df_hash['ViolationIP'] != 'NA']
    HashExtractedIp = df_hash[~(df_hash['ViolationIP'].isin(final_tpi['IOCDetails']))].reset_index(drop=True)
    try:
        HashExtractedIp = HashExtractedIp[HashExtractedIp.VT_Detection.astype(int) >= 5]
    except:
        pass
    HashExtractedIp = HashExtractedIp[['ViolationIP','Country']]
    final_tpi = final_tpi.append(HashExtractedIp)

    

#---------------- Program Start Here---------------
def creatTpi(df):
    global final_tpi
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



    tpi_ipFunc(df_ip)
    tpi_domainFunc(df_domain)
    tpi_HashFunc(df_hash)
    final_tpi = final_tpi.assign(Firstdate = Firstdate)
    final_tpi = final_tpi.assign(Lastdate = Firstdate)
    final_tpi = final_tpi.assign(sourceOfIoc = sourceOfIoc)
    final_tpi = final_tpi.assign(Remark = Remark)
    final_tpi = final_tpi.assign(Risk = Risk)
    final_tpi = final_tpi.assign(Count = '1')


#final_tpi.to_csv('FinalTpi.csv',header=True,columns=["Firstdate","Lastdate","IOCDetails","Country","sourceOfIoc","Remark","Risk"])
def tpi(request):
    return render(request, 'dashboard/tpi.html')

@csrf_exempt    
def tpi_res(request):
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
                final_tpi.to_csv(response,sep=';',float_format='%.2f',index=False,decimal=",",header=True,columns=["Firstdate","Lastdate","IOCDetails","Country","sourceOfIoc","Count","Remark","Risk"])

                #return HttpResponse(request.POST.get('daterange1'))
                return response


            else:
                return HttpResponse("File not Found")
        except  Exception as e:
            print(e)
            return HttpResponse("Wrong File {}".format(e))
    else:
        return HttpResponse("Failed")




