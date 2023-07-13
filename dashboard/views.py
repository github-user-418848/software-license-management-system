from django.shortcuts import render

def home(request):
    context = {}
    return render(request, 'dashboard/home.html', context)