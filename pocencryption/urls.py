from django.urls import path

from . import views

urlpatterns = [
    path('encrypt',views.encrypt, name='encrypt'),
    path('decrypt',views.decrypt, name='decrypt'),
    path('savekey',views.savekey, name='savekey'),
    path('encryptapi',views.encryptapi,name='encryptapi'),
    path('decryptapi',views.decryptapi,name='edecryptapi'),
    path('getdata',views.getdata)

]