from django.shortcuts import render, redirect, get_object_or_404
from .models import *
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import user_passes_test
from django.db.models.functions import TruncDate
from django.db.models import Count
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
import uuid
from django.db.models import Q
import openpyxl
from django.http import HttpResponse
from openpyxl import Workbook
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
import re
from django.utils.dateparse import parse_date
from .utils import BLOCKED_REGEX
from django.db.models import Count, Q
from django.contrib.auth import update_session_auth_hash


# def index(request):
#     if request.method == 'POST' and request.FILES.get('image'):
#         name = request.POST.get('name')
#         image = request.FILES['image']
#
#         if not name:
#             return JsonResponse({'status': 'error', 'message': 'Name is required.'})
#
#         upload = Upload.objects.create(name=name, image=image)
#         upload.save()
#         return JsonResponse({'status': 'success', 'name': upload.name, 'image_url': upload.image.url})
#
#     # For GET requests, just render the template
#     return render(request, 'index.html')





def is_superuser(user):
    return user.is_authenticated and user.is_superuser


from django.views.decorators.cache import never_cache


MAX_ATTEMPTS = 5
BLOCK_HOURS = 5

def superuser_login(request):
    if request.user.is_authenticated and request.user.is_superuser:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        if not username or not password:
            messages.error(request, "All fields are required.")
            return redirect('superuser_login')

        attempt, _ = LoginAttempt.objects.get_or_create(username=username)

        # 🔒 Check block
        if attempt.is_blocked():
            remaining = attempt.blocked_until - timezone.now()
            hours = int(remaining.total_seconds() // 3600)
            messages.error(
                request,
                f"Account locked due to multiple failed attempts. Try again in {hours} hour(s)."
            )
            return redirect('superuser_login')

        user = authenticate(request, username=username, password=password)

        if user is None:
            attempt.attempts += 1
            attempt.save()

            if attempt.attempts >= MAX_ATTEMPTS:
                attempt.block(hours=BLOCK_HOURS)
                messages.error(
                    request,
                    "Too many failed attempts. Account locked for 5 hours."
                )
            else:
                left = MAX_ATTEMPTS - attempt.attempts
                messages.error(
                    request,
                    f"Invalid credentials. {left} attempt(s) remaining."
                )

            return redirect('superuser_login')

        if not user.is_superuser:
            messages.error(request, "Access denied. Superuser only.")
            return redirect('superuser_login')

        # ✅ SUCCESS → reset attempts
        attempt.reset()

        login(request, user)
        return redirect('dashboard')

    return render(request, 'login.html')


@login_required
@user_passes_test(lambda u: u.is_superuser)
def superuser_change_password(request):
    if request.method == "POST":
        current_password = request.POST.get("current_password", "").strip()
        new_password = request.POST.get("new_password", "").strip()
        confirm_password = request.POST.get("confirm_password", "").strip()

        # Basic validation
        if not current_password or not new_password or not confirm_password:
            messages.error(request, "All fields are required.")
            return redirect("superuser_change_password")

        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return redirect("superuser_change_password")

        if len(new_password) < 6:
            messages.error(request, "Password must be at least 6 characters.")
            return redirect("superuser_change_password")

        # Verify current password
        if not request.user.check_password(current_password):
            messages.error(request, "Current password is incorrect.")
            return redirect("superuser_change_password")

        # Set new password
        request.user.set_password(new_password)
        request.user.save()

        # 🔐 Keep user logged in
        update_session_auth_hash(request, request.user)

        messages.success(request, "Password changed successfully.")
        return redirect("superuser_change_password")

    return render(request, "change_password.html")



def superuser_logout(request):
    logout(request)
    return redirect('superuser_login')

@never_cache
@login_required(login_url='/login/')
@user_passes_test(lambda u: u.is_superuser)
def dashboard(request):
    today = timezone.now().date()
    start_date = today - timedelta(days=6)

    # ================= GRAPH DATA (UPLOADS) =================
    raw_uploads = (
        Upload.objects
        .filter(created_at__date__gte=start_date)
        .annotate(day=TruncDate('created_at'))
        .values('day')
        .annotate(count=Count('id'))
        .order_by('day')
    )

    upload_map = {u['day']: u['count'] for u in raw_uploads}

    labels, data = [], []
    for i in range(7):
        day = start_date + timedelta(days=i)
        labels.append(day.strftime('%d %b'))
        data.append(upload_map.get(day, 0))

    # ================= COUNTS =================
    total_uploads = Upload.objects.count()
    unread_uploads = Upload.objects.filter(is_opened=False).count()  # unread count
    total_categories = Category.objects.count()
    total_users = Userlogin.objects.count()
    total_data = Data.objects.count()

    # ================= DATA TABLE =================
    recent_data = (
        Data.objects
        .select_related('category', 'subcategory', 'state', 'district')
        .order_by('-created_at')[:10]
    )

    # ================= UPLOADS =================
    recent_uploads = Upload.objects.order_by('-created_at')[:10]

    # ================= USERS =================
    recent_users = Userlogin.objects.order_by('-last_login')[:10]

    context = {
        # graph
        'labels': labels,
        'data': data,

        # counts
        'total_uploads': total_uploads,
        'unread_uploads': unread_uploads,  # add unread count
        'total_categories': total_categories,
        'total_users': total_users,
        'total_data': total_data,

        # tables
        'recent_data': recent_data,
        'recent_uploads': recent_uploads,

        # users
        'recent_users': recent_users,
    }

    return render(request, 'dashboard.html', context)

@never_cache
@login_required(login_url='/login/')
@user_passes_test(lambda u: u.is_superuser)
def category(request):
    categories = Category.objects.order_by("-created_at")
    subcategories = Subcategory.objects.select_related("category").order_by("-created_at")

    edit_category = None
    edit_subcategory = None

    if request.method == "POST":
        action = request.POST.get("action")

        # ---------- CATEGORY ----------
        if action == "add_category":
            Category.objects.create(name=request.POST.get("name"))

        elif action == "edit_category":
            cat = get_object_or_404(Category, id=request.POST.get("id"))
            cat.name = request.POST.get("name")
            cat.save()

        # ---------- SUBCATEGORY ----------
        elif action == "add_subcategory":
            Subcategory.objects.create(
                name=request.POST.get("name"),
                category_id=request.POST.get("category")
            )

        elif action == "edit_subcategory":
            sub = get_object_or_404(Subcategory, id=request.POST.get("id"))
            sub.name = request.POST.get("name")
            sub.category_id = request.POST.get("category")
            sub.save()

        return redirect("category")

    # ---------- EDIT ----------
    if "edit_category" in request.GET:
        edit_category = get_object_or_404(Category, id=request.GET.get("edit_category"))

    if "edit_subcategory" in request.GET:
        edit_subcategory = get_object_or_404(Subcategory, id=request.GET.get("edit_subcategory"))

    # ---------- DELETE ----------
    if "delete_category" in request.GET:
        get_object_or_404(Category, id=request.GET.get("delete_category")).delete()
        return redirect("category")

    if "delete_subcategory" in request.GET:
        get_object_or_404(Subcategory, id=request.GET.get("delete_subcategory")).delete()
        return redirect("category")

    return render(
        request,
        "category.html",
        {
            "categories": categories,
            "subcategories": subcategories,
            "edit_category": edit_category,
            "edit_subcategory": edit_subcategory,
        },
    )


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import never_cache


@never_cache
@login_required(login_url='/login/')
@user_passes_test(lambda u: u.is_superuser)
def state_district(request):
    states = State.objects.order_by("-created_at")
    districts = District.objects.select_related("state").order_by("-created_at")

    edit_state = None
    edit_district = None

    if request.method == "POST":
        action = request.POST.get("action")

        # ---------- STATE ----------
        if action == "add_state":
            State.objects.create(
                name=request.POST.get("name")
            )

        elif action == "edit_state":
            state = get_object_or_404(State, id=request.POST.get("id"))
            state.name = request.POST.get("name")
            state.save()

        # ---------- DISTRICT ----------
        elif action == "add_district":
            District.objects.create(
                name=request.POST.get("name"),
                state_id=request.POST.get("state")
            )

        elif action == "edit_district":
            district = get_object_or_404(District, id=request.POST.get("id"))
            district.name = request.POST.get("name")
            district.state_id = request.POST.get("state")
            district.save()

        return redirect("state_district")

    # ---------- EDIT ----------
    if "edit_state" in request.GET:
        edit_state = get_object_or_404(
            State, id=request.GET.get("edit_state")
        )

    if "edit_district" in request.GET:
        edit_district = get_object_or_404(
            District, id=request.GET.get("edit_district")
        )

    # ---------- DELETE ----------
    if "delete_state" in request.GET:
        get_object_or_404(
            State, id=request.GET.get("delete_state")
        ).delete()
        return redirect("state_district")

    if "delete_district" in request.GET:
        get_object_or_404(
            District, id=request.GET.get("delete_district")
        ).delete()
        return redirect("state_district")

    return render(
        request,
        "state.html",
        {
            "states": states,
            "districts": districts,
            "edit_state": edit_state,
            "edit_district": edit_district,
        },
    )


@never_cache
@login_required(login_url='/login/')
@user_passes_test(lambda u: u.is_superuser)
def inbox(request):
    uploads = Upload.objects.all().order_by("is_opened", "-created_at")
    # False (not opened) comes first automatically

    # ---- FILTERS ----
    name = request.GET.get("name")
    status = request.GET.get("status")
    date = request.GET.get("date")
    remarks = request.GET.get("remarks")   # ✅ NEW

    if name:
        uploads = uploads.filter(name__icontains=name)

    if remarks:   # ✅ NEW
        uploads = uploads.filter(remarks__icontains=remarks)

    if status == "opened":
        uploads = uploads.filter(is_opened=True)
    elif status == "not_opened":
        uploads = uploads.filter(is_opened=False)

    if date:
        uploads = uploads.filter(created_at__date=date)

    return render(request, "inbox.html", {
        "uploads": uploads,
        "filters": {   # optional but useful
            "name": name,
            "remarks": remarks,
            "status": status,
            "date": date
        }
    })




# views.py
# @login_required
# def open_upload(request, pk):
#     upload = get_object_or_404(Upload, pk=pk)
#     upload.is_opened = True
#     upload.save()
#     return redirect(upload.image.url)  # opens image in new tab


@never_cache
@login_required(login_url='/login/')
@user_passes_test(lambda u: u.is_superuser)
def delete_upload(request, pk):
    upload = get_object_or_404(Upload, pk=pk)
    upload.delete()
    return redirect("inbox")

@never_cache
@login_required(login_url='/login/')
@user_passes_test(lambda u: u.is_superuser)
def open_upload(request, pk):
    upload = get_object_or_404(Upload, pk=pk)

    if not upload.is_opened:
        upload.is_opened = True
        upload.save()

    return JsonResponse({
        "url": upload.image.url
    })


@never_cache
@login_required(login_url='/login/')
@user_passes_test(lambda u: u.is_superuser)
def data(request):
    if request.method == "POST":
        # Use the logged-in user's username
        current_user = request.user.username if request.user.is_authenticated else "Unknown"

        Data.objects.create(
            id="DT" + uuid.uuid4().hex[:3].upper(),
            name=request.POST.get("name"),
            category_id=request.POST.get("category"),
            subcategory_id=request.POST.get("subcategory"),
            location=request.POST.get("location"),
            state_id=request.POST.get("state"),
            district_id=request.POST.get("district"),
            phone=request.POST.get("phone"),
            email=request.POST.get("email"),
            remarks=request.POST.get("remarks"),
            data_given=request.POST.get("data_given"),
            staff=request.POST.get("staff"),
            user=current_user,  # ✅ set to logged-in superuser
            source=request.POST.get("source"),

            # ✅ checkbox handling
            paid=request.POST.get("paid") == "on",
        )

        return redirect("/data?success=1")

    context = {
        "categories": Category.objects.all(),
        "states": State.objects.all(),
    }
    return render(request, "data.html", context)


def get_subcategories(request, category_id):
    subcats = Subcategory.objects.filter(category_id=category_id)
    data = [{"id": s.id, "name": s.name} for s in subcats]
    return JsonResponse(data, safe=False)


def get_districts(request, state_id):
    districts = District.objects.filter(state_id=state_id)
    data = [{"id": d.id, "name": d.name} for d in districts]
    return JsonResponse(data, safe=False)

@never_cache
@login_required(login_url='/login/')
@user_passes_test(lambda u: u.is_superuser)
def data_list(request):

    # ===================== EDIT SAVE =====================
    if request.method == "POST" and request.POST.get("edit_id"):
        obj = get_object_or_404(Data, id=request.POST.get("edit_id"))

        obj.name = request.POST.get("name", "")
        obj.phone = request.POST.get("phone", "")
        obj.email = request.POST.get("email", "")
        obj.location = request.POST.get("location", "")
        obj.data_given = request.POST.get("data_given", "")
        obj.staff = request.POST.get("staff", "")
        obj.source = request.POST.get("source", "")
        obj.remarks = request.POST.get("remarks", "")
        obj.paid = bool(request.POST.get("paid"))

        # 🔗 Foreign Keys (safe)
        obj.category_id = request.POST.get("category") or None
        obj.subcategory_id = request.POST.get("subcategory") or None
        obj.state_id = request.POST.get("state") or None
        obj.district_id = request.POST.get("district") or None

        # ✅ Always set the logged-in superuser as the user
        if request.user.is_authenticated:
            obj.user = request.user.username

        obj.save()

        return redirect(request.path)  # prevents resubmit on refresh

    # ===================== LIST & FILTER =====================
    qs = Data.objects.select_related(
        "category", "subcategory", "state", "district"
    ).order_by("-created_at")

    search = request.GET.get("search", "").strip()
    if search:
        qs = qs.filter(
            Q(name__icontains=search) |
            Q(phone__icontains=search) |
            Q(email__icontains=search) |
            Q(location__icontains=search) |
            Q(id__icontains=search)
        )

    category = request.GET.get("category")
    subcategory = request.GET.get("subcategory")
    state = request.GET.get("state")
    district = request.GET.get("district")
    date = request.GET.get("date")

    if category:
        qs = qs.filter(category_id=category)

    if subcategory and category:
        qs = qs.filter(subcategory_id=subcategory)

    if state:
        qs = qs.filter(state_id=state)

    if district and state:
        qs = qs.filter(district_id=district)

    if date:
        qs = qs.filter(created_at__date=date)

    return render(request, "uploads.html", {
        "data_list": qs,
        "categories": Category.objects.all(),
        "subcategories": Subcategory.objects.all(),
        "states": State.objects.all(),
        "districts": District.objects.all(),
    })

@never_cache
@login_required(login_url='/login/')
@user_passes_test(lambda u: u.is_superuser)
def data_export(request):
    # Create workbook and sheet
    wb = Workbook()
    ws = wb.active
    ws.title = "Data Export"

    # Define headers
    headers = [
         "Name", "Category", "Subcategory", "Location",
        "State", "District", "Phone", "Email", "Remarks",
        "Data Given", "Staff", "User", "Source", "Paid",
        "Date"
    ]
    ws.append(headers)

    # Fetch data
    data_list = Data.objects.all().select_related(
        "category", "subcategory", "state", "district"
    )

    for d in data_list:
        ws.append([

            d.name,
            d.category.name if d.category else "",
            d.subcategory.name if d.subcategory else "",
            d.location,
            d.state.name if d.state else "",
            d.district.name if d.district else "",
            d.phone,
            d.email,
            d.remarks,
            d.data_given,
            d.staff,
            d.user,
            d.source,
            "Paid" if d.paid else "Unpaid",
            d.created_at.date()  # Only date
        ])

    # Apply proper date format to "Created At" column (column 16)
    for row in ws.iter_rows(min_row=2, min_col=16, max_col=16):
        for cell in row:
            cell.number_format = "DD-MM-YYYY"

    # Prepare response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )
    response['Content-Disposition'] = 'attachment; filename=DataExport.xlsx'

    wb.save(response)
    return response


@never_cache
@login_required(login_url='/login/')
@user_passes_test(lambda u: u.is_superuser)
def usercreate(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "").strip()
        confirm_password = request.POST.get("confirm_password", "").strip()

        if not username or not password or not confirm_password:
            messages.error(request, "All fields are required.")
            return redirect(request.path)

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect(request.path)

        # Check if username already exists
        if Userlogin.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect(request.path)

        # Create new user
        Userlogin.objects.create(
            id="C" + uuid.uuid4().hex[:4].upper(),
            username=username,
            password=password  # ⚠️ For production, hash the password!
        )

        messages.success(request, f"User {username} created successfully.")
        return redirect(request.path)

    return render(request, "usercreate.html")


# LOGIN VIEW

BLOCKED_REGEX = re.compile(
    r"(--|;|'|\"|/\*|\*/|\b(select|insert|delete|drop|update|union|or)\b|https?://|www\.|\.com|\.net|\.org)",
    re.IGNORECASE
)

@csrf_protect
@require_http_methods(["GET", "POST"])
def userlogin(request):
    # ---------------- AUTO REDIRECT IF LOGGED IN ----------------
    if request.session.get('user_id'):
        return redirect('index')

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "").strip()

        # ---------------- VALIDATION ----------------
        if not username or not password:
            messages.error(request, "All fields are required.")
            return redirect('userlogin')

        if len(password) < 6:
            messages.error(request, "Password must be at least 6 characters.")
            return redirect('userlogin')

        # Block dangerous input
        import re
        BLOCKED_REGEX = re.compile(
            r"(--|;|'|\"|/\*|\*/|<script|</script>|\b(select|insert|delete|drop|update|union|or)\b|https?:\/\/|www\.|\.com|\.net|\.org)",
            re.IGNORECASE
        )
        if BLOCKED_REGEX.search(username) or BLOCKED_REGEX.search(password):
            messages.error(request, "Invalid input detected.")
            return redirect('userlogin')

        # ---------------- AUTHENTICATE USER ----------------
        try:
            user = Userlogin.objects.get(username=username, password=password)

            # ---------------- CHECK IF USER IS ACTIVE ----------------
            if not user.is_active:
                messages.error(request, "Your account is disabled. Please contact admin.")
                return redirect('userlogin')

            # ---------------- SESSION ----------------
            request.session['user_id'] = user.id
            request.session['username'] = user.username

            # ---------------- HANDLE REMEMBER ME ----------------
            remember = request.POST.get('remember')
            if remember:
                request.session.set_expiry(60 * 60 * 24 * 30)  # 30 days
            else:
                request.session.set_expiry(0)  # expire on browser close

            return redirect('index')

        except Userlogin.DoesNotExist:
            messages.error(request, "Invalid username or password.")
            return redirect('userlogin')

    return render(request, "userlogin.html")



def index(request):
    user_id = request.session.get('user_id')

    # ---------------- AJAX AUTH CHECK ----------------
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        if not user_id:
            return JsonResponse(
                {'status': 'error', 'message': 'Session expired'},
                status=401
            )

    # ---------------- NORMAL PAGE AUTH ----------------
    if not user_id:
        return redirect('userlogin')

    try:
        user = Userlogin.objects.get(id=user_id)
    except Userlogin.DoesNotExist:
        request.session.flush()
        return redirect('userlogin')

    # ---------------- IMAGE UPLOAD ----------------
    if request.method == 'POST' and request.FILES.get('image'):
        try:
            name = request.POST.get('name', '').strip()
            remarks = request.POST.get('remarks', '').strip()
            image = request.FILES.get('image')

            if not name:
                return JsonResponse(
                    {'status': 'error', 'message': 'Name is required'},
                    status=400
                )

            upload = Upload.objects.create(
                user=user,
                name=name,
                image=image,
                remarks=remarks if remarks else None
            )

            return JsonResponse({
                'status': 'success',
                'image_url': upload.image.url,
                'name': upload.name,
                'remarks': upload.remarks,
                'created_at': upload.created_at.strftime('%Y-%m-%d %H:%M')
            })

        except Exception as e:
            print("UPLOAD ERROR:", e)
            return JsonResponse(
                {'status': 'error', 'message': 'Server error'},
                status=500
            )

    # ---------------- PAGE LOAD ----------------
    context = {
        'username': request.session.get('username'),
        'user_uploads': Upload.objects.filter(user=user).order_by('-created_at'),
    }

    return render(request, 'index.html', context)




def userlogout(request):
    request.session.flush()  # Clear session
    return redirect('userlogin')


@never_cache
@login_required(login_url='/login/')
@user_passes_test(lambda u: u.is_superuser)
def userlist(request):
    users = Userlogin.objects.all().order_by('-last_login')  # all users

    search_query = request.GET.get('search', '')
    if search_query:
        users = users.filter(Q(username__icontains=search_query) | Q(id__icontains=search_query))

    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    if start_date:
        users = users.filter(last_login__date__gte=parse_date(start_date))
    if end_date:
        users = users.filter(last_login__date__lte=parse_date(end_date))

    users = users.annotate(upload_count=Count('uploads'))

    # Handle Enable / Disable via POST
    if request.method == "POST":
        action = request.POST.get('action')
        user_id = request.POST.get('user_id')
        try:
            user = Userlogin.objects.get(id=user_id)
            if action == 'disable':
                user.is_active = False
            elif action == 'enable':
                user.is_active = True
            user.save()
            return JsonResponse({
                'status': 'success',
                'new_status': 'active' if user.is_active else 'disabled'
            })
        except Userlogin.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'}, status=404)

    # AJAX fetch
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        data = []
        for user in users:
            data.append({
                'id': user.id,
                'username': user.username,
                'last_login': user.last_login.strftime("%d %b %Y %H:%M:%S") if user.last_login else '',
                'upload_count': user.upload_count,
                'is_active': user.is_active
            })
        return JsonResponse({'users': data})

    context = {
        'users': users,
        'total_users': users.count(),
        'total_uploads': Upload.objects.count(),
        'search_query': search_query,
        'start_date': start_date,
        'end_date': end_date
    }
    return render(request, 'userlist.html', context)


@login_required
def unread_uploads_count(request):
    count = Upload.objects.filter(is_opened=False).count()
    return JsonResponse({'unread_count': count})



