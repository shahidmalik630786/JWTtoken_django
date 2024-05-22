from django.urls import path
from app1 import views

urlpatterns = [
    path('register/', views.UserRegisteration.as_view()),
    path('login/', views.UserLoginView.as_view()),
    path('profile/', views.UserProfile.as_view()),
    path('changepassword/', views.UserChangePasswordView.as_view()),
    path('resetpassword/', views.SendResetPasswordView.as_view()),
   path('resetpasswordhandel/<uid>/<token>/', views.HandelPasswordResetView.as_view(), name='reset_password_handle'),






]