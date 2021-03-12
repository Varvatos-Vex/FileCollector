from django.shortcuts import render, redirect 
from django.http import HttpResponse

def otx(request):
    return render(request, 'dashboard/otxAV.html')