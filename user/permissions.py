from rest_framework import permissions


class UpdateOwnProfile(permissions.BasePermission):
    """Allow user to edit their profile."""
    def has_object_permission(self, request, view, obj):
        print(obj.id)
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.id == request.user.id
