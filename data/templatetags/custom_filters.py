from django import template

register = template.Library()

@register.filter
def get_name_by_id(items, id):
    """
    Given a list of objects (items) and an id, return the name of the matching object.
    Example usage in template:
    {{ categories|get_name_by_id:request.GET.category }}
    """
    if not items or not id:
        return ''
    try:
        id = int(id)
    except (ValueError, TypeError):
        return ''
    for item in items:
        if getattr(item, 'id', None) == id:
            return getattr(item, 'name', '')
    return ''
