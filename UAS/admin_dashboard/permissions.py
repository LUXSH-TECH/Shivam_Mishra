from rest_framework.permissions import BasePermission
from accounts.models import UserRoles, Role
from admin_dashboard.models import ViewAccess


# class DynamicRolePermission(BasePermission):
#     """
#     Permission class that checks view access dynamically from the database.
#     """
#     def has_permission(self, request, view):
#         view_name = f"{view.__module__}.{view.__class__.__name__}" 
#         user_roles = UserRoles.objects.filter(user=request.user).values_list('role', flat=True)
#         return ViewAccess.objects.filter(view_name=view_name, roles__id__in=user_roles).exists()
    

class DynamicRolePermission(BasePermission):
    """
    Checks if the user has access to a view & specific action (read, write, delete).
    """

    def has_permission(self, request, view):
        view_name = f"{view.__module__}.{view.__class__.__name__}"
        action = request.method.lower()  # "get" -> read, "post" -> write, "delete" -> delete

        # Get the user's role
        try:
            user_role = UserRoles.objects.get(user=request.user).role
        except UserRoles.DoesNotExist:
            return False  # User has no assigned role

        # Check if user's role has access to the view
        if not ViewAccess.objects.filter(view_name=view_name, roles=user_role).exists():
            return False

        # Check if the role has the required action-based permission
        required_permission = f"can_{action}_{view_name.split('.')[-1].lower()}"  # e.g., "can_read_userlistview"
        return user_role.permissions.filter(codename=required_permission).exists()
