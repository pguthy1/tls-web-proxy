README.txt: Final Project - C2S Web Proxy
-------------------------------------------------------------------------------
Name: Prasana Guthy
CruzID: pguthy
ID: 1688198
-------------------------------------------------------------------------------
List of Files:
Makefile: found in root directory name lab3-pguthy
    includes `make all` (equivalent to `make`)
    also includes `make clean` target to clean up executables and object files.

Source Code: found in src
    proxymain.c - Main file setting up threads and signal handling functions.
    ssl_example.h - header file with common configuration options and macros.
    tls_client.c - Functions for creating a TLS connection and communicating back to client.
    tls_client.h - header for the above file with prototypes and macros.
    tcp_module.c - Functions for running Reliable File Transfer client.
    tcp_module.h - header for the above file with prototypes and macros.
    http_request.c - Functions from my lab1 with useful functions.
    http_request.h - header for the above file with prototypes.
    http_module.c - Implements functions for retrieving+verifying http requests and handling input errors.
    http_module.h - header for the above file with prototypes.
    http_helper.c - Implements helper functions for the http module
    http_helper.h - header for the above file with prototypes.
    site_filter.c - Implements functions for loading and reloading forbidden sites list
    site_filter.h - header for the above file with prototypes.
    custom_regex.c - generalized regex functions used for input validation.
    custom_regex.h - header for the above file with prototypes.
    input_verify.c - generalized boolean functions for verifying input is correct 
    input_verify.h - header for the above file with prototypes.


Test Code: found in src/test (Not meant for use, by default won't be used by makefile)
    check_http.c - Unit tests for http proxy functions.
    test.sh - bash script for running proxy and example clients

Documentation: found in doc
    design.pdf - Design document with architecture diagram, code attribution, usage guide,
    and test cases performed.

Code Attributions:
See the end of the design pdf for detailed code attributions.