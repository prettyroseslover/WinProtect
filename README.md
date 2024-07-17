# WinProtect
This piece of code protects files from being deleted, read, renamed, etc. unless you have admin rights \
Files to protect are given in the config file -- `templates.tbl` (file1*.txt, file2.doc, etc.)\
To stop the program from managing file access one need to provide a password (stored in a hashed form in the first line of `templates.tbl`)\
Basically, a little project to get to know WinAPI.
