from rest_framework.permissions import BasePermission

class IsAdminOrSpecificAdmin(BasePermission):
    """
    Custom permission to only allow admins or specific admin to access the view.
    """

    def has_permission(self, request, view):
        # Check if the user is authenticated and is an admin
        print(request.user.is_admin,"You are not an admin")
        if request.user.is_authenticated and request.user.is_admin:
            print(request.user.is_admin,"You are not an admin")
            return True
        # Check if the user is authenticated and has specific admin role
        
        return False
