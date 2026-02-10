import random
import string
from django.db.models import Count

CHARS = string.ascii_uppercase + string.digits  # A-Z + 0-9


def generate_auto_id(model, field_name="id", prefix=""):
    for length in (3, 4):  # max 4 only
        max_possible = len(CHARS) ** length
        used = model.objects.aggregate(c=Count(field_name))["c"]

        if used >= max_possible:
            continue

        while True:
            code = prefix + "".join(random.choices(CHARS, k=length))
            if not model.objects.filter(**{field_name: code}).exists():
                return code

    raise ValueError("All possible ID combinations exhausted")
