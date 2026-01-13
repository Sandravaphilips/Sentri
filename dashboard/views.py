from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.views.generic import TemplateView

from apikeys.models import APIKey
from security.models import SecurityEvent


class UserDashboardView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/overview.html"
    paginate_by = 20

    def get_context_data(self, **kwargs):
        user = self.request.user
        context = super().get_context_data(**kwargs)

        events_qs = (
            SecurityEvent.objects
            .filter(user=user)
            .order_by("-created_at")
        )

        paginator = Paginator(events_qs, self.paginate_by)
        page_number = self.request.GET.get("page")
        page_obj = paginator.get_page(page_number)

        context.update({
            "user_obj": user,
            "api_key_count": APIKey.objects.filter(
                user=user, is_revoked=False
            ).count(),
            "page_obj": page_obj,
            "recent_events": page_obj,
            "is_paginated": page_obj.has_other_pages(),
        })

        return context
