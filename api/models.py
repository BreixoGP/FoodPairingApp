import secrets

from django.contrib.auth.models import AbstractUser
from django.db import models

class AppUser(AbstractUser):
	email = models.EmailField(unique=True)

	groups = models.ManyToManyField(
		'auth.Group',
		related_name='appuser_groups',
		blank=True,
		help_text='The groups this user belongs to.',
		verbose_name='groups'
	)
	user_permissions = models.ManyToManyField(
		'auth.Permission',
		related_name='appuser_permissions',
		blank=True,
		help_text='Specific permissions for this user.',
		verbose_name='user permissions'
	)

class UserSession(models.Model):
	user = models.ForeignKey(AppUser, on_delete=models.CASCADE)
	token = models.CharField(max_length=64, unique=True, default=secrets.token_hex(16))
	created_at = models.DateTimeField(auto_now_add=True)

class FlavorProfile(models.Model):
	name = models.CharField(max_length=50)

	def __str__(self):
		return self.name

class Ingredient(models.Model):
	name = models.CharField(max_length=100)
	flavor_profiles = models.ManyToManyField(FlavorProfile, through='IngredientFlavor')
	def __str__(self):
		return self.name

class IngredientFlavor(models.Model):
	ingredient = models.ForeignKey(Ingredient, on_delete=models.CASCADE)
	flavor = models.ForeignKey(FlavorProfile, on_delete=models.CASCADE)
	intensity = models.IntegerField(default=5)
	cooking_method = models.CharField(max_length=50, blank=True, null=True)

class Pairing(models.Model):
	ingredients = models.ManyToManyField(Ingredient)
	score = models.IntegerField()
	reason = models.TextField()
