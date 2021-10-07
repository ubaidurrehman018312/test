from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import BadHeaderError, send_mail
from django.db.models.query_utils import Q
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .forms import *
from .forms import UserRegistrationForm


def login_form(request):
    """show login form"""

    content = {"form": LoginForm()}
    return render(request, "login.html", content)


def authentication(request):
    """check the username and password in database"""

    user_name = request.POST["username"]
    password = request.POST["password"]
    user = authenticate(request, username=user_name, password=password)

    if user is not None:
        login(request, user)
        return render(request, "logout.html")
    else:
        return HttpResponse("username and password doesnot match")


def home(request):
    """show home page"""
    return render(request, "home.html")


def logout_user(request):
    """show logout form"""
    logout(request)
    return render(request, "login.html")


def register(request):
    """show the registration form"""
    if request.method == "POST":

        form = UserRegistrationForm(request.POST)

        if form.is_valid():
            form.save()

            messages.success(
                request, f"Your account has been created. You can log in now!"
            )

            send_mail(
                "Signup",
                f"welcome! {request.POST['username']} you are signup successfully",
                settings.EMAIL_HOST_USER,
                [request.POST["email"]],
                fail_silently=False,
            )

            return redirect("../login")
    else:
        form = UserRegistrationForm()

    context = {"form": form}
    return render(request, "register.html", context)


def password_reset_request(request):

    if request.method == "POST":

        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data["email"]

            associated_users = User.objects.filter(Q(email=data))
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "password_reset_email.txt"
                    c = {
                        "email": user.email,
                        "domain": "127.0.0.1:8000",
                        "site_name": "Website",
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        "token": default_token_generator.make_token(user),
                        "protocol": "http",
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(
                            subject,
                            email,
                            "admin@example.com",
                            [user.email],
                            fail_silently=False,
                        )
                    except BadHeaderError:
                        return HttpResponse("Invalid header found.")
                    return redirect("/password_reset/done/")
    password_reset_form = PasswordResetForm()

    return render(
        request=request,
        template_name="password_reset.html",
        context={"password_reset_form": password_reset_form},
    )


def password_confirm(request):

    if request.method == "POST":

        user_name = request.POST["user_name"]
        new_password = request.POST["new_password"]
        confirm_password = request.POST["confirm_password"]

        if new_password == confirm_password:
            u = User.objects.get(username=user_name)
            u.set_password(new_password)
            u.save()
        return render(request=request, template_name="password_reset_complete.html")
