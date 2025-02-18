from django.urls import path
from admin_dashboard.views import *

urlpatterns = [
    #             <-----User management -----> 
    path('create_user/', CreateUserView.as_view(), name ='create user'),
    path('user_list/', UserListView.as_view(), name ='user list'),
    path('user_details/<int:id>/', GetUserDetailView.as_view(), name ='user details'),
    path('update_user/', UpdateUserDetailsView.as_view(), name ='update user'),
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
    path('delete_role/', DeleteRoleView.as_view(), name ='delete role'),
    #             <----- UserRole urls ----->
]
