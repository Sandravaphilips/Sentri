from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import get_user_model
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST
from django.views.generic import TemplateView, ListView, DetailView

from apikeys.models import APIKey
from security.models import SecurityEvent
from security.mixins import StaffRequiredMixin
from security.services import RemediationService

User = get_user_model()


class AdminSecurityOverviewView(StaffRequiredMixin, TemplateView):
    template_name = "admin/security/overview.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            "total_users": User.objects.count(),
            "locked_users": User.objects.filter(
                account_locked_until__isnull=False
            ).count(),
            "compromised_users": User.objects.filter(is_compromised=True).count(),
            "recent_events": SecurityEvent.objects.order_by("-created_at")[:25],
        })
        return context


class AdminUserListView(StaffRequiredMixin, ListView):
    template_name = "admin/security/user_list.html"
    model = User
    context_object_name = "users"
    ordering = ["-updated_at"]
    paginate_by = 25


class AdminUserDetailView(StaffRequiredMixin, DetailView):
    template_name = "admin/security/user_detail.html"
    model = User
    pk_url_kwarg = "user_id"
    context_object_name = "user_obj"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.object

        events = SecurityEvent.objects.filter(user=user).order_by("-created_at")
        paginator = Paginator(events, 20)

        page_number = self.request.GET.get("page")
        page_obj = paginator.get_page(page_number)

        context.update({
            "security_events": page_obj,
            "page_obj": page_obj,
            "is_paginated": page_obj.has_other_pages(),
            "api_key_count": APIKey.objects.filter(
                user=user, is_revoked=False
            ).count(),
        })
        return context


@staff_member_required
@require_POST
def admin_unlock_user(request, user_id):
    user = get_object_or_404(User, id=user_id)

    RemediationService.unlock_account(
        user=user,
        reason="admin_manual_unlock",
    )

    messages.success(request, "Account unlocked.")
    return redirect("security_admin:user_detail", user_id=user.id)


@staff_member_required
@require_POST
def admin_clear_compromise(request, user_id):
    user = get_object_or_404(User, id=user_id)

    RemediationService.clear_compromise(
        user=user,
        reason="admin_manual_clear",
    )

    messages.success(request, "Compromise flag cleared.")
    return redirect("security_admin:user_detail", user_id=user.id)


@staff_member_required
@require_POST
def admin_revoke_api_keys(request, user_id):
    user = get_object_or_404(User, id=user_id)

    RemediationService.revoke_all_api_keys(
        user=user,
        reason="admin_manual_revoke",
    )

    messages.success(request, "All API keys revoked.")
    return redirect("security_admin:user_detail", user_id=user.id)
