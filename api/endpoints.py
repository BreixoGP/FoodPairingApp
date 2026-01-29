import json

from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from api.models import AppUser, UserSession, Ingredient, FlavorProfile, Pairing, IngredientFlavor


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
@csrf_exempt
def ingredients_list(request):
	user = authenticate_request(request)
	if not user:
		return JsonResponse({"error": "Unauthorized"}, status=401)

	if request.method == 'GET':
		data = []

		for ing in Ingredient.objects.all():
			variants = {}

			for f in IngredientFlavor.objects.filter(ingredient=ing):
				method = f.cooking_method or "default"

				if method not in variants:
					variants[method] = []

				variants[method].append({
					"flavor": f.flavor.name,
					"intensity": f.intensity
				})

			data.append({
				"id": ing.pk,
				"name": ing.name,
				"variants": variants
			})

		return JsonResponse({"ingredients": data}, status=200)

	elif request.method == 'POST':
		if not user or not user.is_superuser:
			return JsonResponse({"error": "Forbidden"}, status=403)

		body = json.loads(request.body)
		name = body.get("name")

		if not name:
			return JsonResponse({"error": "Missing name"}, status=400)

		ingredient = Ingredient.objects.create(name=name)

		return JsonResponse({
			"id": ingredient.pk,
			"name": ingredient.name
		}, status=201)
	return JsonResponse({"error": "HTTP method not allowed"}, status=405)


@csrf_exempt
def pairings_list(request):
	user = authenticate_request(request)
	if not user:
		return JsonResponse({"error": "Unauthorized"}, status=401)

	if request.method != "POST":
		return JsonResponse({"error": "HTTP method not allowed"}, status=405)

	try:
		body = json.loads(request.body)
	except json.JSONDecodeError:
		return JsonResponse({"error": "Invalid JSON"}, status=400)

	ingredient_ids = body.get("ingredient_ids", [])

	if not ingredient_ids:
		return JsonResponse({"error": "No ingredients provided"}, status=400)

	if len(ingredient_ids) > 3:
		return JsonResponse({"error": "Too many ingredients (max 3)"}, status=400)

	ingredients = Ingredient.objects.filter(pk__in=ingredient_ids)

	# 1️⃣ Obtener variantes por ingrediente
	variants_per_ingredient = []

	for ing in ingredients:
		variants = IngredientFlavor.objects.filter(ingredient=ing)

		methods = {}
		for v in variants:
			methods.setdefault(v.cooking_method or "raw", []).append(v)

		variants_per_ingredient.append({
			"ingredient": ing,
			"methods": methods
		})

	# 2️⃣ Generar combinaciones de métodos
	method_combinations = list(product(*[
		list(v["methods"].keys()) for v in variants_per_ingredient
	]))

	results = []

	# 3️⃣ Para cada combinación → construir perfil base
	for combo in method_combinations:
		base_profile = {}
		base_description = []

		for idx, method in enumerate(combo):
			ing = variants_per_ingredient[idx]["ingredient"]
			flavors = variants_per_ingredient[idx]["methods"][method]

			base_description.append({
				"ingredient": ing.name,
				"method": method
			})

			for f in flavors:
				base_profile[f.flavor.name] = (
					base_profile.get(f.flavor.name, 0) + f.intensity
				)

		# 4️⃣ Comparar con otros ingredientes
		pairings = []

		for candidate in Ingredient.objects.exclude(pk__in=ingredient_ids):
			score = 0
			common_flavors = []

			for f in IngredientFlavor.objects.filter(ingredient=candidate):
				if f.flavor.name in base_profile:
					score += min(base_profile[f.flavor.name], f.intensity)
					common_flavors.append(f.flavor.name)

			if score >= 5:
				pairings.append({
					"ingredient": candidate.name,
					"score": score,
					"common_flavors": list(set(common_flavors))
				})

		if pairings:
			pairings.sort(key=lambda x: x["score"], reverse=True)
			results.append({
				"base": base_description,
				"pairings": pairings
			})

	return JsonResponse({"results": results}, status=200)