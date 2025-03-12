from django.urls import path
from admin_dashboard.views import *

urlpatterns = [
    #             <-----User management -----> 
    path('create_user/', CreateUserView.as_view(), name ='create user'),
    path('user_list/', UserListView.as_view(), name ='user list'),
    path('user_details/<int:id>/', GetUserDetailView.as_view(), name ='user details'),
    path('update_user/', UpdateUserDetailsView.as_view(), name ='update user'),
    path('toggle_mfa/', ToggleMFAView.as_view(), name='toggle-mfa'),
    path('delete_user/<int:id>/', DeleteUserView.as_view(), name ='delete user'),
    #             <----- permission urls -----> 
    path('create_permission/', CreatePermissionView.as_view(), name ='create permission'),
    path('permission_details/<int:id>', GetPermissionDetailsView.as_view(), name ='permission details'),
    path('update_permission/', UpdatePermissionView.as_view(), name ='update permission'),
    path('delete_permission/<int:id>/', DeletePermissionView.as_view(), name ='delete permission'),
    #             <----- Role urls -----> 
    path('create_role/', CreateRoleView.as_view(), name ='create role'),
    path('role_details/<int:id>/', GetRoleDetailsView.as_view(), name ='role details'),
    path('update_role/', UpdateRoleView.as_view(), name = 'udpate role'),
    path('delete_role/<int:id>', DeleteRoleView.as_view(), name ='delete role'),
    #             <----- UserRole urls ----->
    path('create_user_role/', CreateUserRoleView.as_view(), name='create-user-role'),
    path('user_role_details/<int:id>/', GetUserRoleDetailsView.as_view(), name='user-role-details'),
    path('update_role/', UpdateUserRoleView.as_view(), name='update-role'),
    path('delete_role/<int:id>', DeleteUserRoleView.as_view(), name='delete_role'),
    #             <----- ViewAccess urls ----->
    path('list_create_view_access/', ViewAccessListCreateView.as_view(), name='list-create-view-access'),
    path('view_access_details/<int:id>/', GetViewAccessDetailsView.as_view(), name='view-access-details'),
    path('update_view_access/', ViewAccessUpdateView.as_view(), name='update-view-access'),
    path('delete_view_access/<int:id>/', ViewAccessDeleteView.as_view(), name='delete-view-access'),
    #             <----- reports urls ----->
    path('user_activity_list/', UserActivityListView.as_view(), name='user-activity-list'),
    path('export_audit_report/', UserActivityCSVReportView.as_view(), name='export-audit-report'),
]