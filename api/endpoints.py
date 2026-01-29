import json

from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from api.models import AppUser, UserSession


@csrf_exempt
def register(request):
	if request.method != 'POST':
		return JsonResponse({"error": "HTTP method not allowed"}, status=405)

	try:
		body = json.loads(request.body)
	except json.JSONDecodeError:
		return JsonResponse({"error": "Invalid JSON"}, status=400)

	username = body.get("username")
	email = body.get("email")
	password = body.get("password")

	# Basic validation
	if not username or not password or not email:
		return JsonResponse({"error": "Missing fields"}, status=400)

	# Check uniqueness
	if AppUser.objects.filter(username=username).exists():
		return JsonResponse({"error": "Username already exists"}, status=409)
	if AppUser.objects.filter(email=email).exists():
		return JsonResponse({"error": "Email already in use"}, status=409)

	# Create user
	user = AppUser.objects.create(
		username=username,
		email=email,
		password=make_password(password)  # encrypt password
	)

	# Create session automatically
	session = UserSession.objects.create(user=user)

	return JsonResponse({
		"message": "User created successfully",
		"user_id": user.pk,
		"username": user.username,
		"token": session.token
	}, status=201)


@csrf_exempt
def login(request):
	if request.method != "POST":
		return JsonResponse({"error": "HTTP method not allowed"}, status=405)

	try:
		body = json.loads(request.body)
	except json.JSONDecodeError:
		return JsonResponse({"error": "Invalid JSON"}, status=400)

	username = body.get("username")
	password = body.get("password")

	if not username or not password:
		return JsonResponse({"error": "Missing fields"}, status=400)

	try:
		user = AppUser.objects.get(username=username)
	except AppUser.DoesNotExist:
		return JsonResponse({"error": "User not found"}, status=404)

	if not check_password(password, user.password):
		return JsonResponse({"error": "Incorrect password"}, status=401)

	# Check for existing active session
	session, created = UserSession.objects.get_or_create(user=user)

	return JsonResponse({
		"message": "Login successful",
		"token": session.token,
		"user_id": user.pk,
		"username": user.username
	}, status=200)


@csrf_exempt
def user_detail(request, id):
	user = authenticate_request(request)
	if not user:
		return JsonResponse({"error": "Unauthorized"}, status=401)

	if user.pk != id:
		return JsonResponse({"error": "You cannot access another user"}, status=403)

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
			return JsonResponse({"error": "Invalid JSON"}, status=400)

		username = body.get("username")
		email = body.get("email")
		password = body.get("password")

		if username:
			if AppUser.objects.filter(username=username).exclude(pk=user.pk).exists():
				return JsonResponse({"error": "Username already exists"}, status=409)
			user.username = username

		if email:
			if AppUser.objects.filter(email=email).exclude(pk=user.pk).exists():
				return JsonResponse({"error": "Email already in use"}, status=409)
			user.email = email

		if password:
			user.password = make_password(password)

		user.save()
		return JsonResponse({"message": "User updated successfully"}, status=200)

	elif request.method == 'DELETE':
		user.delete()
		return JsonResponse({"message": "User deleted successfully"}, status=200)

	else:
		return JsonResponse({"error": "HTTP method not allowed"}, status=405)


def authenticate_request(request):
	"""
	Returns the user associated with the token in headers, or None if invalid.
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
