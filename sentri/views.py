from django.views.generic import TemplateView


class HomePageView(TemplateView):
    template_name = 'sentri/home.html'
    navbar_link = 'home'
