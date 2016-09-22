# SSL Certification Expiration Checker

ssl-cert-check is a Bourne shell script that can be used to check and report  on expiring SSL certificates. The script was designed to be run from cron and can e-mail notifications or log alerts through nagios.  

# Example:
<pre>

Print the expiration times for one or more certificates listed in ssldomains:

$ ssl-cert-check -f ssldomains
Host                                            Status       Expires      Days Left
----------------------------------------------- ------------ ------------ ----------
www.prefetch.com:443                            Valid        May 23 2006  218
mail.prefetch.net:993                           Valid        Jun 20 2006  246
gmail.google.com:443                            Valid        Jun 7 2006   233
www.sun.com:443                                 Valid        May 11 2009  1302
www.spotch.com:443                              Connection refused Unknown Unknown
</pre>

Send an e-mail to admin@prefetch.net if a domain listed in ssldomains will expire in the next 60-days:

<pre>
$ ssl-cert-check -a -f ssldomains -q -x 60 -e admin@prefetch.net
</pre>

# Additional Documentation

Documentation And Examples: http://prefetch.net/articles/checkcertificate.html
