from django.contrib.auth.decorators import login_required
from django.http import JsonResponse


def health(request):
    return JsonResponse({"status": "ok"})


def list_users(request):
    return JsonResponse([], safe=False)


@login_required
def user_detail(request, pk):
    return JsonResponse({"id": pk})


@login_required
def me(request):
    return JsonResponse({"id": request.user.id})
