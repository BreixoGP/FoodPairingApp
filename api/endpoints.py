import json

from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from api.models import AppUser, UserSession



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



@csrf_exempt
def user_detail(request, id):
    user = authenticate_request(request)
    if not user:
        return JsonResponse({"error": "No autorizado"}, status=401)

    if user.pk != id:
        return JsonResponse({"error": "No puedes acceder a otro usuario"}, status=403)

    # Ahora podemos usar tu lógica normal de GET, PUT, DELETE
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

        if username:
            if AppUser.objects.filter(username=username).exclude(pk=user.pk).exists():
                return JsonResponse({"error": "Ese nombre de usuario ya existe"}, status=409)
            user.username = username

        if email:
            if AppUser.objects.filter(email=email).exclude(pk=user.pk).exists():
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

def authenticate_request(request):
    """
    Devuelve el usuario asociado al token en headers o None si no hay token válido.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Token "):
        return None

    token = auth_header.split(" ")[1]
    try:
        session = UserSession.objects.get(token=token)
        return session.user
    except UserSession.DoesNotExist:
        return None
