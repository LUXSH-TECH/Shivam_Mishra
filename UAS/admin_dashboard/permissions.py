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

        action_map = {
            "get": "read",
            "post": "write",
            "put": "write",
            "patch": "write",
            "delete": "delete"
        }

        action = action_map.get(request.method.lower(), None)  # "get" -> read, "post" -> write, "delete" -> delete
        if not action:
            return False
    
        # Get the user's role
        try:
            user_role = UserRoles.objects.get(user=request.user).role
            print(f"User Role: {user_role}")
        except UserRoles.DoesNotExist:
            print("User has no assigned role")
            return False  # User has no assigned role

        # Check if user's role has access to the view
        print(f"Checking access for view: {view_name} and role: {user_role}")
        if not ViewAccess.objects.filter(view_name=view_name, roles=user_role).exists():
            print("Access Denied: No entry in ViewAccess for this role and view")
            return False
        
        # Check if the role has the required action-based permission
        required_permission = f"can_{action}_{view_name.split('.')[-1].lower()}"  # e.g., "can_read_userlistview"
        print(f"Required Permission: {required_permission}")

        has_permission = user_role.permission.filter(codename=required_permission).exists()
        print(f"🔍 Role Has Required Permission: {has_permission}")

        if has_permission:
            print("Access Granted")
            return True
        else:
            print(f"Access Denied: Role '{user_role.name}' does not have permission '{required_permission}'")
            return False
