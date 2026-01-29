import json

from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from api.models import AppUser


@csrf_exempt
def user_detail(request, id):
    try:
        user = AppUser.objects.get(id=id)
    except AppUser.DoesNotExist:
        return JsonResponse({"error": "Usuario no encontrado"}, status=404)

    if request.method == 'GET':
        return JsonResponse({
            "id": user.pk,
            "username": user.username,
            "email": user.email
        }, status=200)

    elif request.method == 'PUT':
        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "JSON inválido"}, status=400)

        username = body.get("username")
        email = body.get("email")
        password = body.get("password")

        # Validar unicidad
        if username:
            if AppUser.objects.filter(username=username).exclude(id=user.id).exists():
                return JsonResponse({"error": "Ese nombre de usuario ya existe"}, status=409)
            user.username = username

        if email:
            if AppUser.objects.filter(email=email).exclude(id=user.id).exists():
                return JsonResponse({"error": "Ese email ya está en uso"}, status=409)
            user.email = email

        if password:
            user.password = make_password(password)

        user.save()
        return JsonResponse({"message": "Usuario actualizado"}, status=200)

    elif request.method == 'DELETE':
        user.delete()
        return JsonResponse({"message": "Usuario eliminado"}, status=200)

    else:
        return JsonResponse({"error": "Método HTTP no soportado"}, status=405)

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .models import AppUser
from django.contrib.auth.hashers import make_password

@csrf_exempt
def register(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Método HTTP no soportado"}, status=405)

    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "JSON inválido"}, status=400)

    username = body.get("username")
    email = body.get("email")
    password = body.get("password")

    # Validaciones básicas
    if not username or not password or not email:
        return JsonResponse({"error": "Faltan campos"}, status=400)

    # Verificar unicidad
    if AppUser.objects.filter(username=username).exists():
        return JsonResponse({"error": "Ese nombre de usuario ya existe"}, status=409)
    if AppUser.objects.filter(email=email).exists():
        return JsonResponse({"error": "Ese email ya está en uso"}, status=409)

    # Crear usuario
    user = AppUser.objects.create(
        username=username,
        email=email,
        password=make_password(password)  # encripta la contraseña
    )

    return JsonResponse({"message": "Usuario creado correctamente", "id": user.pk}, status=201)
