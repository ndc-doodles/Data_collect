from django.db import models
from cloudinary.models import CloudinaryField
from django.utils import timezone

from .utils import generate_auto_id


class Category(models.Model):
    id = models.CharField(
        max_length=5,  # C + 4 chars max
        primary_key=True,
        editable=False
    )
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = generate_auto_id(Category, prefix="C")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.id} - {self.name}"


class Subcategory(models.Model):
    id = models.CharField(
        max_length=5,  # S + 4 chars max
        primary_key=True,
        editable=False
    )
    category = models.ForeignKey(
        Category,
        on_delete=models.CASCADE,
        related_name="subcategories"
    )
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = generate_auto_id(Subcategory, prefix="S")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.id} - {self.name}"

class State(models.Model):
    id = models.CharField(
        max_length=5,      # ST + 3 chars OR S + 4 chars (your choice)
        primary_key=True,
        editable=False
    )
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = generate_auto_id(State, prefix="ST")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.id} - {self.name}"

class District(models.Model):
    id = models.CharField(
        max_length=5,      # D + 4 chars
        primary_key=True,
        editable=False
    )
    state = models.ForeignKey(
        State,
        on_delete=models.CASCADE,
        related_name="districts"
    )
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = generate_auto_id(District, prefix="D")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.id} - {self.name}"

class Data(models.Model):
    id = models.CharField(
        max_length=5,
        primary_key=True,
        editable=False
    )
    name = models.CharField(max_length=100)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name="data")
    subcategory = models.ForeignKey(Subcategory, on_delete=models.CASCADE)
    location = models.CharField(max_length=500)
    state = models.ForeignKey(State, on_delete=models.CASCADE)
    district = models.ForeignKey(District, on_delete=models.CASCADE)
    phone = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    remarks = models.TextField(blank=True, null=True)
    data_given = models.CharField(max_length=500)
    staff = models.CharField(max_length=500)
    user = models.CharField(max_length=500)
    source = models.CharField(max_length=500)

    paid = models.BooleanField(default=False)  # ⬅️ checkbox

    created_at = models.DateTimeField(auto_now_add=True)

    class Data(models.Model):
        id = models.CharField(
            max_length=5,
            primary_key=True,
            editable=False
        )
        name = models.CharField(max_length=100)
        category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name="data")
        subcategory = models.ForeignKey(Subcategory, on_delete=models.CASCADE)
        location = models.CharField(max_length=500)
        state = models.ForeignKey(State, on_delete=models.CASCADE)
        district = models.ForeignKey(District, on_delete=models.CASCADE)
        phone = models.CharField(max_length=100)
        email = models.CharField(max_length=100)
        remarks = models.TextField(blank=True, null=True)
        data_given = models.CharField(max_length=500)
        staff = models.CharField(max_length=500)
        user = models.CharField(max_length=500)
        source = models.CharField(max_length=500, blank=True, null=True)

        paid = models.BooleanField(default=False)  # ⬅️ checkbox

        created_at = models.DateTimeField(auto_now_add=True)

class Userlogin(models.Model):
    id = models.CharField(
        max_length=5,  # C + 4 chars max
        primary_key=True,
        editable=False
    )
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    last_login = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)  # Add this field

    def __str__(self):
        return self.username


class Upload(models.Model):
    user = models.ForeignKey('Userlogin', on_delete=models.CASCADE, related_name='uploads')  # link to user
    name = models.CharField(max_length=100)
    image = CloudinaryField('image')
    remarks = models.CharField(max_length=500, blank=True, null=True)
    is_opened = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class LoginAttempt(models.Model):
    username = models.CharField(max_length=150, unique=True)
    attempts = models.PositiveIntegerField(default=0)
    blocked_until = models.DateTimeField(null=True, blank=True)

    def is_blocked(self):
        return self.blocked_until and self.blocked_until > timezone.now()

    def block(self, hours=5):
        self.blocked_until = timezone.now() + timedelta(hours=hours)
        self.attempts = 0
        self.save()

    def reset(self):
        self.attempts = 0
        self.blocked_until = None
        self.save()

    def __str__(self):
        return self.username
















