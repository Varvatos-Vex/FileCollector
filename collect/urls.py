from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [

    path('', views.dashboard, name='dashboard'),
    path('index', views.index, name='index'),
    path('home/', views.home, name='home'),
    path('threatactors/', views.threat, name='threat'),
    path('Report/', views.report, name='report'),
    path('daterange/', views.daterange, name='daterange'),
    path('login/', views.Login, name='login'),
    path('logout/', views.Logout, name='logout'),
    path('FileValidate/', views.ValidateFile, name='validate'),
    path('ajax_calls/search/', views.autocompleteModel,name = 'search'),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)