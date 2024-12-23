package kubiya.tool_manager

# Default deny all access
default allow = false

# List of admin-only functions and tools
admin_tools = {
    "list_active_access_requests", 
    "search_access_requests", 
    "approve_tool_access_request",
    "get_user",
    "search_users",
    "create_group",
    "update_group",
    "delete_group",
    "get_group",
    "list_members",
    "add_member",
    "remove_member",
    "jit_session_revoke_database_access_to_staging",
    "s3_revoke_data_lake_read"
}

restricted_tools = {
    "list_users",
    "list_groups",
    "jit_session_grant_database_access_to_staging",
    "s3_grant_data_lake_read"
}

# Allow Administrators to run admin tools
allow {
    group := input.user.groups[_].name
    group == "Admin"
    admin_tools[input.tool.name]
}

# Allow Administrators to run revoke tools (s3_revoke_*, jit_session_revoke_*)
allow {
    group := input.user.groups[_].name
    group == "Admin"
    not restricted_tools[input.tool.name]
}

# Allow everyone to run everything except:
# - admin tools
# - grant/revoke prefixed tools
allow {
    not admin_tools[input.tool.name]
    not restricted_tools[input.tool.name]
}
