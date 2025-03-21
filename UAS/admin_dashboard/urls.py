from django.urls import path
from admin_dashboard.views import *

urlpatterns = [
    #             <-----User management -----> 
    path('api/create_user/', CreateUserView.as_view(), name ='api-create-user'),
    path('api/user_list/', UserListView.as_view(), name ='api-user-list'),
    path('api/user_details/<int:id>/', GetUserDetailView.as_view(), name ='api-user-details'),
    path('api/update_user/', UpdateUserDetailsView.as_view(), name ='api-update-user'),
    path('api/toggle_mfa/', ToggleMFAView.as_view(), name='toggle-mfa'),
    path('api/delete_user/<int:id>/', DeleteUserView.as_view(), name ='api-delete-user'),
    #             <----- permission urls -----> 
    path('api/create_permission/', CreatePermissionView.as_view(), name ='api-create-permission'),
    path('api/permission_list/', PermissionListView.as_view(), name ='api-permission-list'),
    path('api/permission_details/<int:id>', GetPermissionDetailsView.as_view(), name ='api-permission-details'),
    path('api/update_permission/', UpdatePermissionView.as_view(), name ='api-update-permission'),
    path('api/delete_permission/<int:id>/', DeletePermissionView.as_view(), name ='api-delete-permission'),
    #             <----- Role urls -----> 
    path('api/create_role/', CreateRoleView.as_view(), name ='api-create-role'),
    path('role_details/<int:id>/', GetRoleDetailsView.as_view(), name ='api-role-details'),
    path('update_role/', UpdateRoleView.as_view(), name = 'api-udpate-role'),
    path('delete_role/<int:id>', DeleteRoleView.as_view(), name ='api-delete-role'),
    #             <----- UserRole urls ----->
    path('api/create_user_role/', CreateUserRoleView.as_view(), name='api-create-user-role'),
    path('api/user_role_details/<int:id>/', GetUserRoleDetailsView.as_view(), name='api-user-role-details'),
    path('api/update_role/', UpdateUserRoleView.as_view(), name='api-update-role'),
    path('api/delete_role/<int:id>', DeleteUserRoleView.as_view(), name='api-delete_role'),
    #             <----- ViewAccess urls ----->
    path('api/list_create_view_access/', ViewAccessListCreateView.as_view(), name='api-list-create-view-access'),
    path('api/view_access_details/<int:id>/', GetViewAccessDetailsView.as_view(), name='api-view-access-details'),
    path('api/update_view_access/', ViewAccessUpdateView.as_view(), name='api-update-view-access'),
    path('api/delete_view_access/<int:id>/', ViewAccessDeleteView.as_view(), name='api-delete-view-access'),
    #             <----- reports urls ----->
    path('api/user_activity_list/', UserActivityListView.as_view(), name='api-user-activity-list'),
    path('api/export_audit_report/', UserActivityCSVReportView.as_view(), name='api-export-audit-report'),

    #             <----- user management template urls ----->
    path('create_user/', create_user, name='create-user'),
    path('user_list/', user_list, name='user-list'),
    path('user_details/', user_detail, name='get-user-details'),
    path('toggle_mfa/', toggle_mfa, name='toggle-mfa'),
    path('delete_user/', delete_user, name='delete-user'),
    #             <----- permission management template urls ----->
    path('create_permission/', create_permission, name='create-permission'),
    path('permission_list/', permission_list, name='permission-list'),
    path('permission_details/', permission_details, name='permission-details'),
    path('delete_permission/', delete_permission, name='delete-permission'),
    #             <----- role management template urls ----->
    path('create_role/', create_role, name='create-role'),
    path('role_list/', role_list, name='role-list'),
    path('role_details/', role_details, name='role-details'),
    path('delete_role/', delete_role, name='delete-role'),
    #             <----- user_role management template urls ----->
    path('assign_user_role/', assign_user_role, name='assign-user-role'),
    path('user_role_list/', user_role_list, name='user-role-list'),
    path('user_role_details/', user_role_details, name='user-role-details'),
    path('delete_user_role/', delete_user_role, name='delete-user-role'),
]