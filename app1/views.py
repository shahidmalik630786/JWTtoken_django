from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from app1.serializers import MyUserSerializers,UserLoginSerializer,UserChangePasswordSerializer,SendPasswordResetSerializers,UserPasswordResetSerializer
from app1.models import MyUser
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth import get_user_model
from django.contrib.auth import get_user_model




#generate token manaully
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# Create your views here.
class UserRegisteration(APIView):
   
    def get(self,request,format=None):
        authentication_classes = [JWTAuthentication]
        permission_classes = [IsAuthenticated]

        obj=MyUser.objects.all()
        serializer_data=MyUserSerializers(obj,many=True)
        return Response(serializer_data.data)
    

    def post(self, request):
        serializer= MyUserSerializers(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({"token":token,'msg': 'Registration successful'}, status=status.HTTP_201_CREATED)

        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data.get('email')  # Using validated_data instead of data
            password = serializer.validated_data.get('password')  # Using validated_data instead of data
            user = authenticate(email=email, password=password)
            if user is not None:
                token = RefreshToken.for_user(user)
                return Response({"token": str(token.access_token), 'msg': 'Login successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors': {'non_field_errors': ['Email or password is not valid']}}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfile(APIView):
    def get(self,request,format=None):
        authentication_classes = [JWTAuthentication]
        permission_classes = [IsAuthenticated]

        obj=MyUser.objects.all()
        serializer_data=MyUserSerializers(obj,many=True)
        return Response(serializer_data.data)

class UserChangePasswordView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = UserChangePasswordSerializer(data=request.data, context={'request': request.user})
        
        if serializer.is_valid():
            serializer.update(request.user, serializer.validated_data)
            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendResetPasswordView(APIView):
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = SendPasswordResetSerializers(data=request.data, context={'request': request.user})
        
        if serializer.is_valid():
            # Your logic to send password reset email goes here
            return Response({"message": "Password reset email sent successfully"}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


User = get_user_model()

class HandelPasswordResetView(APIView):
    def post(self, request, uid, token):
        try:
            uid_decoded = urlsafe_base64_decode(uid)
            print("Decoded UID:", uid_decoded)
            uid_str = smart_str(uid_decoded)
            print("Decoded UID (as string):", uid_str)
            user = User.objects.get(id=uid_str)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid user id"}, status=status.HTTP_400_BAD_REQUEST)
        
        if PasswordResetTokenGenerator().check_token(user, token):
            serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)
