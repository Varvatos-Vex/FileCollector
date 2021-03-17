from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views
from . import otxview
from . import tpi_view

urlpatterns = [

    path('', views.dashboard, name='dashboard'),
    path('index', views.index, name='index'),
    path('home/', views.home, name='home'),
    path('threatactors/', views.threat, name='threat'),
    path('Report/', views.report, name='report'),
    path('Otx/', otxview.otx, name='otx'),
    path('tpi/', tpi_view.tpi, name='tpi'),
    path('tpi_res/', tpi_view.tpi_res, name='tpi_res'),
    path('daterange/', views.daterange, name='daterange'),
    path('login/', views.Login, name='login'),
    path('change-pass/', views.changePass, name='change-pass'),
    path('logout/', views.Logout, name='logout'),
    path('FileValidate/', views.ValidateFile, name='validate'),
    path('misp/', otxview.misp, name='misp'),
    path('misp_res/', otxview.misp_res, name='misp_res'),
    path('ajax_calls/search/', views.autocompleteModel,name = 'search'),
    path('ajax_calls/ThreatActorDetails/', views.thretadetails,name = 't_details'),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)