#!/bin/bash
#
# Program: SSL Certificate Check <ssl-cert-check>
#
# Source code home: http://prefetch.net/code/ssl-cert-check
#
# Documentation: http://prefetch.net/articles/checkcertificate.html
#
# Author: Matty < matty91 at gmail dot com >
#
# Current Version: 3.29
#
# Revision History:
#
# Version 3.29
#  - Add the openssl -servername flag if it shows up in help.
#
# Version 3.28
#  - Added  a DEBUG option to assist with debugging folks who use the script
#
# Version 3.27
#  - Allow white spaces to exist in the certificate file list
#  - Add an additional check to pick up bad / non-existent certificates
#  - Add a check to look for the existence of a mail program. Error out if it's not present.
#  - Enable the TLS -servername extension by default - Juergen Knaack & Johan Denoyer
#
# Version 3.26
#  - Allow the certificate type (PEM, DER, NET) to be passed on the command line
#
# Version 3.25
#   - Check for "no route to host" errors -- Dan Doyle
#   - Set RETCODE to 3 (unknown) if a connection error occurs -- Dan Doyle
#   - Documentation fixes
#
# Version 3.24
#   - Utilize the -clcerts option to limit the results to client certificates - Eitan Katznelson
#
# Version 3.23
#   - Fixed typo in date2julian routine -- Ken Cook
#
# Version 3.22
#   - Change the validation option to "-V"
#   - Add a "-v" option to specify a specific protocol version (ssl2, ssl3 or tls)
#
# Version 3.21
#   - Adjust e-mail checking to avoid exiting if notifications aren't enabled -- Nick Anderson
#   - Added the number of days until expiration to the Nagios output -- Nick Anderson
#
# Version 3.20
#   - Fixed a bug in certificate length checking -- Tim Nowaczyk
#
# Version 3.19
#   - Added check to verify the certificate retrieved is valid
#
# Version 3.18
#   - Add support for connecting to FTP servers -- Paul A Sand 
#
# Version 3.17
#   - Add support for connecting to imap servers -- Joerg Pareigis
#
# Version 3.16
#   - Add support for connecting to the mail sbmission port -- Luis E. Munoz
#
# Version 3.15
#   - Adjusted the file checking logic to use the correct certificate -- Maciej Szudejko 
#   - Add sbin to the default search paths for OpenBSD compatibility -- Alex Popov
#   - Use cut instead of substring processing to ensure compatibility -- Alex Popov
#
# Version 3.14
#   - Fixed the Common Name parser to handle DN's where the CN is not the last item 
#     eg. EmailAddr -- Jason Brothers
#   - Added the ability to grab the serial number -- Jason Brothers
#   - Added the "-b" option to print results without a header -- Jason Brothers
#   - Added the "-v" option for certificate validation -- Jason Brothers
#
# Version 3.13
#   - Updated the subject line to include the hostname as well as
#     the common name embedded in the X509 certificate (if it's
#     available) -- idea proposed by Mike Burns 
#
#  Version 3.12
#   - Updated the license to allow redistribution and modification
#
#  Version 3.11
#   - Added ability to comment out lines in files passed
#     to the "-f" option -- Brett Stauner
#   - Fixed comment next to file processing logic
#
#  Version 3.10
#   - Fixed POP3 port -- Simon Matter
#
#  Version 3.9
#    - Switched binary location logic to use which utility
#
#  Version 3.8
#    - Fixed display on 80 column displays
#    - Cleaned up the formatting
#
#  Version 3.7
#    - Fixed bug in NAGIOS tests -- Ben Allen 
#
#  Version 3.6
#    - Added support for certificates stored in PKCS#12 databases -- Ken Gallo
#    - Cleaned up comments
#    - Adjusted variables to be more consistent
#
#  Version 3.5
#    - Added support for NAGIOS -- Quanah Gibson-Mount
#    - Added additional checks for mail -- Quanah Gibson-Mount
#    - Convert tabs to spaces -- Quanah Gibson-Mount
#    - Cleaned up usage() routine
#    - Added additional checks for openssl
#
#  Version 3.4
#   - Added a missing "{" to line 364 -- Ken Gallo
#   - Move mktemp to the start of the main body to avoid errors
#   - Adjusted default binary paths to make sure the script just works
#     w/ Solaris, BSD and Linux hosts
#
#  Version 3.3
#   - Added common name from X.509 certificate file to E-mail body / header -- Doug Curtis
#   - Fixed several documentation errors 
#   - Use mktemp to create temporary files
#   - Convert printf, sed and awk to variables 
#   - Check for printf, sed, awk and mktemp binaries
#   - Add additional logic to make sure mktemp returned a valid temporary file
#
#  Version 3.2
#   - Added option to list certificates in the file passed to "-f".
#
#  Version 3.1
#   - Added handling for starttls for smtp -- Marco Amrein
#   - Added handling for starttls for pop3 (without s) -- Marco Amrein
#   - Removed extra spacing at end of script
#
#  Version 3.0
#   - Added "-i" option to print certificate issuer  
#   - Removed $0 from Subject line of outbound e-mails
#   - Fixed some typographical errors
#   - Removed redundant "-b" option
#
#  Version 2.0
#    - Fixed an issue with e-mails formatting incorrectly
#    - Added additional space to host column -- Darren-Perot Spruell
#    - Replaced GNU date dependency with CHRIS F. A. JOHNSON's 
#      date2julian shell function. This routine can be found on 
#      page 170 of Chris's book "Shell Scripting Recipes: A 
#      Problem-Solution Approach," ISBN #1590594711. Julian function 
#      was created based on a post to comp.unix.shell by Tapani Tarvainen.
#    - Cleaned up function descriptions
#    - Removed several lines of redundant code
#    - Adjusted the help message
#      
#   Version 1.1
#    - Added "-c" flag to report expiration status of a PEM encoded 
#      certificate -- Hampus Lundqvist
#    - Updated the prints messages to display the reason a connection
#      failed (connection refused, connection timeout, bad cert, etc)
#    - Updated the GNU date checking routines
#    - Added checks for each binary required
#    - Added checks for connection timeouts
#    - Added checks for GNU date
#    - Added a "-h" option
#    - Cleaned up the documentation
#
#  Version 1.0
#      Initial Release
#
# Last Updated: 01-05-2016
#
# Purpose: 
#  ssl-cert-check checks to see if a digital certificate in X.509 format
#  has expired. ssl-cert-check can be run in interactive and batch mode,
#  and provides facilities to alarm if a certificate is about to expire.
#
# License: 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
# Requirements:
#   Requires openssl
# 
# Installation: 
#   Copy the shell script to a suitable location
#
# Tested platforms:
#  -- Solaris 9 using /bin/bash
#  -- Solaris 10 using /bin/bash
#  -- OS X 10.4.2 using /bin/bash
#  -- OpenBSD using /bin/sh
#  -- FreeBSD using /bin/sh
#  -- Centos Linux 3, 4, 5 & 6 using /bin/bash
#  -- Redhat Enterprise Linux 3, 4, 5 & 6 using /bin/bash
# 
# Usage:
#  Refer to the usage() sub-routine, or invoke ssl-cert-check 
#  with the "-h" option.
# 
# Examples:
#   Please refer to the following site for documentation and examples:
#   http://prefetch.net/articles/checkcertificate.html

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/ssl/bin:/usr/sfw/bin
export PATH

# Who to page when an expired certificate is detected (cmdline: -e)
ADMIN="root"

# Number of days in the warning threshhold  (cmdline: -x)
WARNDAYS=30

# If QUIET is set to TRUE, don't print anything on the console (cmdline: -q)
QUIET="FALSE"

# Don't send E-mail by default (cmdline: -a)
ALARM="FALSE"

# Don't run as a Nagios plugin by default (cmdline: -n)
NAGIOS="FALSE"

# NULL out the PKCSDBPASSWD variable for later use (cmdline: -k)
PKCSDBPASSWD=""

# Type of certificate (PEM, DER, NET) (cmdline: -t)
CERTTYPE="pem"

# Protocol version to use (cmdline: -v)
VERSION=""

# Enable debugging
DEBUG=0

# Location of system binaries
AWK=$(which awk)
DATE=$(which date)
GREP=$(which grep)
OPENSSL=$(which openssl)
PRINTF=$(which printf)
SED=$(which sed)
MKTEMP=$(which mktemp)

# Try to find a mail client
if [ -f /usr/bin/mailx ]
then
    MAIL="/usr/bin/mailx"
elif [ -f /bin/mail ]
then
    MAIL="/bin/mail"
elif [ -f /usr/bin/mail ]
then
    MAIL="/usr/bin/mail"
elif [ -f /sbin/mail ]
then
    MAIL="/sbin/mail"
elif [ -f /usr/sbin/mail ]
then
    MAIL="/usr/sbin/mail"
else
    MAIL="cantfindit"
fi

# Return code used by nagios. Initialize to 0.
RETCODE=0

# Set the default umask to be somewhat restrictive
umask 077

#############################################################################
# Purpose: Convert a date from MONTH-DAY-YEAR to Julian format
# Acknowledgements: Code was adapted from examples in the book
#                   "Shell Scripting Recipes: A Problem-Solution Approach"
#                   ( ISBN 1590594711 )
# Arguments:
#   $1 -> Month (e.g., 06)
#   $2 -> Day   (e.g., 08)
#   $3 -> Year  (e.g., 2006)
#############################################################################
date2julian() {

    if [ "${1}" != "" ] && [ "${2}" != ""  ] && [ "${3}" != "" ]
    then
        ## Since leap years add aday at the end of February, 
        ## calculations are done from 1 March 0000 (a fictional year)
        d2j_tmpmonth=$((12 * ${3} + ${1} - 3))
        
        ## If it is not yet March, the year is changed to the previous year
        d2j_tmpyear=$(( ${d2j_tmpmonth} / 12))
        
        ## The number of days from 1 March 0000 is calculated
        ## and the number of days from 1 Jan. 4713BC is added 
        echo $(( (734 * ${d2j_tmpmonth} + 15) / 24
                 - 2 * ${d2j_tmpyear} + ${d2j_tmpyear}/4 
                 - ${d2j_tmpyear}/100 + ${d2j_tmpyear}/400 + $2 + 1721119 ))
    else
        echo 0
    fi
}

#############################################################################
# Purpose: Convert a string month into an integer representation
# Arguments:
#   $1 -> Month name (e.g., Sep)
#############################################################################
getmonth() 
{
    case ${1} in
        Jan) echo 1 ;;
        Feb) echo 2 ;;
        Mar) echo 3 ;;
        Apr) echo 4 ;;
        May) echo 5 ;;
        Jun) echo 6 ;;
        Jul) echo 7 ;;
        Aug) echo 8 ;;
        Sep) echo 9 ;;
        Oct) echo 10 ;;
        Nov) echo 11 ;;
        Dec) echo 12 ;;
          *) echo  0 ;;
    esac
}

#############################################################################
# Purpose: Calculate the number of seconds between two dates
# Arguments:
#   $1 -> Date #1
#   $2 -> Date #2
#############################################################################
date_diff() 
{
    if [ "${1}" != "" ] &&  [ "${2}" != "" ]
    then
        echo $((${2} - ${1}))
    else
        echo 0
    fi
}

#####################################################################
# Purpose: Print a line with the expiraton interval
# Arguments:
#   $1 -> Hostname
#   $2 -> TCP Port 
#   $3 -> Status of certification (e.g., expired or valid)
#   $4 -> Date when certificate will expire
#   $5 -> Days left until the certificate will expire 
#   $6 -> Issuer of the certificate
#####################################################################
prints() 
{
    if [ "${QUIET}" != "TRUE" ] && [ "${ISSUER}" = "TRUE" ] && [ "${VALIDATION}" != "TRUE" ]
    then
        MIN_DATE=$(echo $4 | ${AWK} '{ print $1, $2, $4 }')
        if [ "${NAGIOS}" == "TRUE" ]
        then
            ${PRINTF} "%-35s %-17s %-8s %-11s %-4s %-30s\n" "$1:$2" "$6" "$3" "$MIN_DATE" \|days="$5" 
        else
            ${PRINTF} "%-35s %-17s %-8s %-11s %-4s %-30s\n" "$1:$2" "$6" "$3" "$MIN_DATE" "$5" 
        fi
    elif [ "${QUIET}" != "TRUE" ] && [ "${ISSUER}" = "TRUE" ] && [ "${VALIDATION}" == "TRUE" ]
    then
        ${PRINTF} "%-35s %-35s %-32s %-17s\n" "$1:$2" "$7" "$8" "$6"

    elif [ "${QUIET}" != "TRUE" ] && [ "${VALIDATION}" != "TRUE" ]
    then
        MIN_DATE=$(echo $4 | ${AWK} '{ print $1, $2, $4 }')
        if [ "${NAGIOS}" == "TRUE" ]
        then
            ${PRINTF} "%-47s %-12s %-12s %-4s %-30s\n" "$1:$2" "$3" "$MIN_DATE" \|days="$5" 
        else
            ${PRINTF} "%-47s %-12s %-12s %-4s %-30s\n" "$1:$2" "$3" "$MIN_DATE" "$5" 
        fi  
    elif [ "${QUIET}" != "TRUE" ] && [ "${VALIDATION}" == "TRUE" ]
    then
        ${PRINTF} "%-35s %-35s %-32s\n" "$1:$2" "$7" "$8"
    fi
}


####################################################
# Purpose: Print a heading with the relevant columns
# Arguments:
#   None
####################################################
print_heading() 
{
    if [ "${NOHEADER}" != "TRUE" ]
    then 
       if [ "${QUIET}" != "TRUE" ] && [ "${ISSUER}" = "TRUE" ] && [ "${NAGIOS}" != "TRUE" ] && [ "${VALIDATION}" != "TRUE" ]
       then
           ${PRINTF} "\n%-35s %-17s %-8s %-11s %-4s\n" "Host" "Issuer" "Status" "Expires" "Days"
           echo "----------------------------------- ----------------- -------- ----------- ----"

       elif [ "${QUIET}" != "TRUE" ] && [ "${ISSUER}" = "TRUE" ] && [ "${NAGIOS}" != "TRUE" ] && [ "${VALIDATION}" == "TRUE" ]
       then
           ${PRINTF} "\n%-35s %-35s %-32s %-17s\n" "Host" "Common Name" "Serial #" "Issuer"
           echo "----------------------------------- ----------------------------------- -------------------------------- -----------------"
    
       elif [ "${QUIET}" != "TRUE" ] && [ "${NAGIOS}" != "TRUE" ] && [ "${VALIDATION}" != "TRUE" ]
       then
           ${PRINTF} "\n%-47s %-12s %-12s %-4s\n" "Host" "Status" "Expires" "Days" 
           echo "----------------------------------------------- ------------ ------------ ----"
    
       elif [ "${QUIET}" != "TRUE" ] && [ "${NAGIOS}" != "TRUE" ] && [ "${VALIDATION}" == "TRUE" ]
       then
           ${PRINTF} "\n%-35s %-35s %-32s\n" "Host" "Common Name" "Serial #"
           echo "----------------------------------- ----------------------------------- --------------------------------"
        fi
    fi
}


##########################################
# Purpose: Describe how the script works
# Arguments:
#   None
##########################################
usage() 
{
    echo "Usage: $0 [ -e email address ] [ -x days ] [-q] [-a] [-b] [-h] [-i] [-n] [-v]"
    echo "       { [ -s common_name ] && [ -p port] } || { [ -f cert_file ] } || { [ -c certificate file ] }" 
    echo ""
    echo "  -a                : Send a warning message through E-mail"
    echo "  -b                : Will not print header"
    echo "  -c cert file      : Print the expiration date for the PEM or PKCS12 formatted certificate in cert file"
    echo "  -e E-mail address : E-mail address to send expiration notices"
    echo "  -f cert file      : File with a list of FQDNs and ports"
    echo "  -h                : Print this screen"
    echo "  -i                : Print the issuer of the certificate"
    echo "  -k password       : PKCS12 file password"
    echo "  -n                : Run as a Nagios plugin"
    echo "  -p port           : Port to connect to (interactive mode)"
    echo "  -s commmon name   : Server to connect to (interactive mode)"
    echo "  -t type           : Specify the certificate type"
    echo "  -q                : Don't print anything on the console"
    echo "  -v                : Specify a specific protocol version to use (tls, ssl2, ssl3)"
    echo "  -V                : Only print validation data"
    echo "  -x days           : Certificate expiration interval (eg. if cert_date < days)"
    echo ""
}


##########################################################################
# Purpose: Connect to a server ($1) and port ($2) to see if a certificate
#          has expired
# Arguments:
#   $1 -> Server name
#   $2 -> TCP port to connect to
##########################################################################
check_server_status() {

    if [ "_${2}" = "_smtp" -o "_${2}" = "_25" ]
    then
        TLSFLAG="-starttls smtp"

    elif [ "_${2}" = "_ftp" -o "_${2}" = "_21" ]
    then
        TLSFLAG="-starttls ftp"

    elif [ "_${2}" = "_pop3" -o "_${2}" = "_110" ]
    then
        TLSFLAG="-starttls pop3"
    
    elif [ "_${2}" = "_imap" -o "_${2}" = "_143" ]
    then
        TLSFLAG="-starttls imap"

    elif [ "_${2}" = "_submission" -o "_${2}" = "_587" ]
    then
        TLSFLAG="-starttls smtp -port ${2}"
    else
        TLSFLAG=""
    fi

    if [ "${VERSION}" != "" ]
    then
        VER="-${VERSION}"
    fi

    if [ "${TLSSERVERNAME}" = "TRUE" ]
    then
         TLSFLAG="${TLSFLAG} -servername $1"
    fi

    echo "" | ${OPENSSL} s_client ${VER} -connect ${1}:${2} ${TLSFLAG} 2> ${ERROR_TMP} 1> ${CERT_TMP}

    if ${GREP} -i  "Connection refused" ${ERROR_TMP} > /dev/null
    then
        prints ${1} ${2} "Connection refused" "Unknown"  
        RETCODE=3

    elif ${GREP} -i "No route to host" ${ERROR_TMP} > /dev/null
    then
        prints ${1} ${2} "No route to host" "Unknown"  
        RETCODE=3

    elif ${GREP} -i "gethostbyname failure" ${ERROR_TMP} > /dev/null
    then
        prints ${1} ${2} "Cannot resolve domain" "Unknown" 
        RETCODE=3
    
    elif ${GREP} -i "Operation timed out" ${ERROR_TMP} > /dev/null
    then
        prints ${1} ${2} "Operation timed out" "Unknown"  
        RETCODE=3
 
    elif ${GREP} -i "ssl handshake failure" ${ERROR_TMP} > /dev/null
    then
        prints ${1} ${2} "SSL handshake failed" "Unknown"  
        RETCODE=3

    elif ${GREP} -i "connect: Connection timed out" ${ERROR_TMP} > /dev/null
    then
        prints ${1} ${2} "Connection timed out" "Unknown"  
        RETCODE=3
    
    else
        check_file_status ${CERT_TMP} $1 $2
    fi
}

#####################################################
### Check the expiration status of a certificate file
### Accepts three parameters:
###  $1 -> certificate file to process
###  $2 -> Server name
###  $3 -> Port number of certificate
#####################################################
check_file_status() {

    CERTFILE=${1}
    HOST=${2}
    PORT=${3}

    ### Check to make sure the certificate file exists
    if [ ! -r ${CERTFILE} ] || [ ! -s ${CERTFILE} ]
    then
        echo "ERROR: The file named ${CERTFILE} is unreadable or doesn't exist"
        echo "ERROR: Please check to make sure the certificate for ${HOST}:${PORT} is valid"
        RETCODE=1
        return
    fi

    ### Grab the expiration date from the X.509 certificate
    if [ "${PKCSDBPASSWD}" != "" ]
    then
        # Extract the certificate from the PKCS#12 database, and
        # send the informational message to /dev/null
        ${OPENSSL} pkcs12 -nokeys -in ${CERTFILE} \
                   -out ${CERT_TMP} -clcerts -password pass:${PKCSDBPASSWD} 2> /dev/null
           
        # Extract the expiration date from the certificate
        CERTDATE=$(${OPENSSL} x509 -in ${CERT_TMP} -enddate -noout | \
                 ${SED} 's/notAfter\=//')

        # Extract the issuer from the certificate
        CERTISSUER=$(${OPENSSL} x509 -in ${CERT_TMP} -issuer -noout | \
                    ${AWK} 'BEGIN {RS="/" } $0 ~ /^O=/ \
                                  { print substr($0,3,17)}')

        ### Grab the common name (CN) from the X.509 certificate
        COMMONNAME=$(${OPENSSL} x509 -in ${CERT_TMP} -subject -noout | \
                   ${SED} -e 's/.*CN=//' | \
				   ${SED} -e 's/\/.*//')
        
	### Grab the serial number from the X.509 certificate
        SERIAL=$(${OPENSSL} x509 -in ${CERT_TMP} -serial -noout | \
                   ${SED} -e 's/serial=//')
    else
        # Extract the expiration date from the ceriticate
        CERTDATE=$(${OPENSSL} x509 -in ${CERTFILE} -enddate -noout -inform ${CERTTYPE} | \
                 ${SED} 's/notAfter\=//')

        # Extract the issuer from the certificate
        CERTISSUER=$(${OPENSSL} x509 -in ${CERTFILE} -issuer -noout -inform ${CERTTYPE} | \
                   ${AWK} 'BEGIN {RS="/" } $0 ~ /^O=/ { print substr($0,3,17)}')

        ### Grab the common name (CN) from the X.509 certificate
        COMMONNAME=$(${OPENSSL} x509 -in ${CERTFILE} -subject -noout -inform ${CERTTYPE} | \
                   ${SED} -e 's/.*CN=//' | \
				   ${SED} -e 's/\/.*//')
	### Grab the serial number from the X.509 certificate
        SERIAL=$(${OPENSSL} x509 -in ${CERTFILE} -serial -noout -inform ${CERTTYPE} | \
                   ${SED} -e 's/serial=//')
    fi

    ### Split the result into parameters, and pass the relevant pieces to date2julian
    set -- ${CERTDATE}
    MONTH=$(getmonth ${1})

    # Convert the date to seconds, and get the diff between NOW and the expiration date
    CERTJULIAN=$(date2julian ${MONTH#0} ${2#0} ${4})
    CERTDIFF=$(date_diff ${NOWJULIAN} ${CERTJULIAN})

    if [ ${CERTDIFF} -lt 0 ]
    then
        if [ "${ALARM}" = "TRUE" ]
        then
            echo "The SSL certificate for ${HOST} \"(CN: ${COMMONNAME})\" has expired!" \
                 | ${MAIL} -s "Certificate for ${HOST} \"(CN: ${COMMONNAME})\" has expired!" ${ADMIN}
        fi

        prints ${HOST} ${PORT} "Expired" "${CERTDATE}" "${CERTDIFF}" "${CERTISSUER}" "${COMMONNAME}" "${SERIAL}"
        RETCODE=2

    elif [ ${CERTDIFF} -lt ${WARNDAYS} ]
    then
        if [ "${ALARM}" = "TRUE" ]
        then
            echo "The SSL certificate for ${HOST} \"(CN: ${COMMONNAME})\" will expire on ${CERTDATE}" \
                 | ${MAIL} -s "Certificate for ${HOST} \"(CN: ${COMMONNAME})\" will expire in ${WARNDAYS}-days or less" ${ADMIN}
        fi
        prints ${HOST} ${PORT} "Expiring" "${CERTDATE}" "${CERTDIFF}" "${CERTISSUER}" "${COMMONNAME}" "${SERIAL}" 
        RETCODE=1

    else
        prints ${HOST} ${PORT} "Valid" "${CERTDATE}" "${CERTDIFF}" "${CERTISSUER}" "${COMMONNAME}" "${SERIAL}"
        RETCODE=0
    fi
}

#################################
### Start of main program
#################################
while getopts abinv:e:f:c:hk:p:s:t:qx:V option
do
    case "${option}"
    in
        a) ALARM="TRUE";;
        b) NOHEADER="TRUE";;
        c) CERTFILE=${OPTARG};;
        e) ADMIN=${OPTARG};;
        f) SERVERFILE=$OPTARG;;
        h) usage
           exit 1;;
        i) ISSUER="TRUE";;
        k) PKCSDBPASSWD=${OPTARG};;
        n) NAGIOS="TRUE";;
        p) PORT=$OPTARG;;
        s) HOST=$OPTARG;;
        t) CERTTYPE=$OPTARG;;
        q) QUIET="TRUE";;
        v) VERSION=$OPTARG;;
        V) VALIDATION="TRUE";;
        x) WARNDAYS=$OPTARG;;
       \?) usage
           exit 1;;
    esac
done

### Check to make sure a openssl utility is available
if [ ! -f ${OPENSSL} ]
then
    echo "ERROR: The openssl binary does not exist in ${OPENSSL}."
    echo "FIX: Please modify the \${OPENSSL} variable in the program header."
    exit 1
fi

### Check to make sure a date utility is available
if [ ! -f ${DATE} ]
then
    echo "ERROR: The date binary does not exist in ${DATE} ."
    echo "FIX: Please modify the \${DATE} variable in the program header."
    exit 1
fi

### Check to make sure a grep utility is available
if [ ! -f ${GREP} ]
then
    echo "ERROR: The grep binary does not exist in ${GREP} ."
    echo "FIX: Please modify the \${GREP} variable in the program header."
    exit 1
fi

### Check to make sure the mktemp and printf utilities are available
if [ ! -f ${MKTEMP} ] || [ ! -f ${PRINTF} ]
then
    echo "ERROR: Unable to locate the mktemp or printf binary."
    echo "FIX: Please modify the \${MKTEMP} and \${PRINTF} variables in the program header."
    exit 1
fi

### Check to make sure the sed and awk binaries are available
if [ ! -f ${SED} ] || [ ! -f ${AWK} ]
then
    echo "ERROR: Unable to locate the sed or awk binary."
    echo "FIX: Please modify the \${SED} and \${AWK} variables in the program header."
    exit 1
fi

### Check to make sure a mail client is available it automated notifications are requested
if [ "${ALARM}" = "TRUE" ] && [ ! -f ${MAIL} ]
then
    echo "ERROR: You enabled automated alerts, but the mail binary could not be found."
    echo "FIX: Please modify the ${MAIL} variable in the program header."
    exit 1
fi

# Send along the servername when TLS is used
if ${OPENSSL} s_client -h 2>&1 | grep '-servername' > /dev/null
then
    TLSSERVERNAME="TRUE"
else
    TLSSERVERNAME="FALSE"
fi

# Place to stash temporary files
CERT_TMP=$($MKTEMP  /var/tmp/cert.XXXXXX)
ERROR_TMP=$($MKTEMP /var/tmp/error.XXXXXX)

### Baseline the dates so we have something to compare to
MONTH=$(${DATE} "+%m")
DAY=$(${DATE} "+%d")
YEAR=$(${DATE} "+%Y")
NOWJULIAN=$(date2julian ${MONTH#0} ${DAY#0} ${YEAR})

### Touch the files prior to using them
if [ ! -z "${CERT_TMP}" ] && [ ! -z "${ERROR_TMP}" ]
then
    touch ${CERT_TMP} ${ERROR_TMP}
else
    echo "ERROR: Problem creating temporary files"
    echo "FIX: Check that mktemp works on your system"
    exit 1
fi

### If a HOST and PORT were passed on the cmdline, use those values
if [ "${HOST}" != "" ] && [ "${PORT}" != "" ]
then
    print_heading
    check_server_status "${HOST}" "${PORT}"

### If a file is passed to the "-f" option on the command line, check 
### each certificate or server / port combination in the file to see if 
### they are about to expire
elif [ -f "${SERVERFILE}" ]
then
    print_heading
    egrep -v '(^#|^$)' ${SERVERFILE} |  while read HOST PORT
    do
        if [ "$PORT" = "FILE" ]
        then
            check_file_status ${HOST} "FILE" "${HOST}"
        else
            check_server_status "${HOST}" "${PORT}"
        fi
    done

### Check to see if the certificate in CERTFILE is about to expire
elif [ "${CERTFILE}" != "" ]
then
    print_heading
    check_file_status ${CERTFILE} "FILE"  "${CERTFILE}"

### There was an error, so print a detailed usage message and exit
else
    usage
    exit 1
fi

### Remove the temporary files
if [ $DEBUG == 1 ]
then
    echo "DEBUG: Certificate temporary file:"
    cat ${CERT_TMP}
    echo "DEBUG: Runtime information file:"
    cat ${ERROR_TMP}
fi

rm -f ${CERT_TMP} ${ERROR_TMP}

### Exit with a success indicator
if [ "${NAGIOS}" = "TRUE" ]; then
    exit $RETCODE
else
    exit 0
fi
