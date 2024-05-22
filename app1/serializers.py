from rest_framework import serializers
from app1.models import MyUser
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth import get_user_model



class MyUserSerializers(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    class Meta:
        model = MyUser
        fields = ["id","email", "name","password", "password2", "tc"]
        extra_kwargs = {
            'password':{'write_only':True}
        }

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password')
        if password!= password2:
            raise serializers.ValidationError("Passwords must match")
        return attrs
    
    def create(self, validate_data):
        return MyUser.objects.create_user(**validate_data)
    
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = MyUser
        fields = ['email', 'password']



class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')  # Changed from password to password2
        if password != password2:
            raise serializers.ValidationError("Passwords and confirm password must match")
        return attrs

    def update(self, instance, validated_data):
        instance.set_password(validated_data['password'])
        instance.save()
        return instance





class SendPasswordResetSerializers(serializers.Serializer):
    email = serializers.EmailField(max_length=255)  

    def validate(self, attrs):
        email = attrs.get('email')
        if MyUser.objects.filter(email=email).exists():
            user = MyUser.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_link = f'http://127.0.0.1:8000/api/user/reset/{uid}/{token}'
            print (reset_link,"*****************")
            attrs['reset_link'] = reset_link
        else:
            raise serializers.ValidationError("Email does not exist")
        return attrs


User = get_user_model()

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        uid = self.context.get('uid')
        token = self.context.get('token')
        
        # Check if passwords match
        if password != password2:
            raise serializers.ValidationError("Passwords and confirm password must match")

        # Decode uid and retrieve user
        try:
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid user id")

        # Check if token is valid
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Invalid or expired token")

         # Set new password for the user
        user.set_password(password)
        user.save()

        return attrs

    def create(self, validated_data):
        # Since this serializer doesn't create any instance, just return the validated data
        return validated_data