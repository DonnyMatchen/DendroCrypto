# DESCRIPTION
This is a small utility application that handles things directly and indirectly related to encryption.

# LINUX USERS
Please note that the linux version comes with a file called `run`.  This is a bash script that runs the application in the correct working directory.

# FUTURE PLANS
* file reading and writing
* Xarc format handling

# BEST PRACTICES
For secret key cryptography, the recommended method is AES/CBC/PKCSSPadding which requires an initialization vector (IV).  Base64 encoding is more compact than with Hexadecimal.  All modes are provided for completeness and for decrypting material from other sources.