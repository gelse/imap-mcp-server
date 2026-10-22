"""On-disk persistence for users, accounts and mail artifacts.

All state writes go through ``fs_safe`` (0700 directories, 0600 secret files,
atomic replaces); concrete stores arrive with M03/M04.
"""
