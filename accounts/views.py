from django.shortcuts import render, redirect
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views.generic import View
from django_ratelimit.decorators import ratelimit

from accounts.serializers import SignupSerializer


# Create your views here.
@method_decorator(
    ratelimit(key='ip', rate='5/m', block=True),
    name='dispatch'
)
class SignUpView(View):
    template_name = 'registration/signup.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request, *args, **kwargs):
        serializer = SignupSerializer(data=request.POST)

        if serializer.is_valid():
            serializer.save()
            return redirect('login')

        return render(
            request,
            self.template_name,
            {'errors': serializer.errors, 'data': request.POST},
        )


