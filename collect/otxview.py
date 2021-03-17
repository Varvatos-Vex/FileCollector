from django.shortcuts import render, redirect 
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt,csrf_protect
from .models import MispGalaxies
import pandas as pd
import io

def otx(request):
    return render(request, 'dashboard/otxAV.html')








#--------------------------------Upadte MISP Data
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