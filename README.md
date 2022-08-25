# DESCRIPTION
This is a small utility application that handles things directly and indirectly related to encryption.

# FUTURE PLANS
* implementation of elliptic curve cryptography and key generation
* hash truncation
* file reading and writing
* DendroFinance format handling

# ABBREVIATIONS
* PIVI - password and indexed IV
* PSIV - password and specified IV
* KSIV - specified key and specified IV

# BEST PRACTICES
For secret key cryptography, the recommended method is AES/CBC/PKCSSPadding which requires an initialization vector (IV).  Base64 encoding is more compact than with Hexadecimal.  All modes are provided for completeness and for decrypting material from other sources.