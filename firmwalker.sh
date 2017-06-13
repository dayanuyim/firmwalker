#!/usr/bin/env bash
set -e
set -u

function usage {
	echo "Usage:"
	echo "$0 {path to extracted file system of firmware}\
 {optional: name of the file to store results - defaults to firmwalker.txt}"
	echo "Example: ./$0 linksys/fmk/rootfs/"
	exit 1
}

function msg {
    echo "$1" | tee -a $FILE
}

function getArray {
    array=() # Create array
    while IFS= read -r line
    do
        array+=("$line")
    done < "$1"
}

function sect {
    if [ ! -z "$1" ]; then
        echo "\`\`\`"
        echo "$1"
        echo "\`\`\`"
    fi
}

function md_tbl {
    if [ ! -z "$2" ]; then
        msg "| # | $1 |"
        msg "|--:|:---|"
        echo "$2"
    fi
}

# Check for arguments
if [[ $# -gt 2 || $# -lt 1 ]]; then
    usage
fi

# Set variables
FIRMDIR=$1
if [[ $# -eq 2 ]]; then
    FILE=$2
else
    FILE="firmwalker.txt"
fi

#append '/'
if [[ "$FIRMDIR" != "*/" ]]; then
    FIRMDIR="$FIRMDIR/"
fi

# Remove previous file if it exists, is a file and doesn't point somewhere
if [[ -e "$FILE" && ! -h "$FILE" && -f "$FILE" ]]; then
    rm -f $FILE
fi

# Perform searches =============================================

msg "# Filesystem Vuls"
#msg "## Firmware Directory"
#msg $FIRMDIR

msg "## Password Files"
getArray "data/passfiles"
passfiles=("${array[@]}")
for passfile  in "${passfiles[@]}"
do
    msg "### $passfile"
    text=$(find $FIRMDIR -name $passfile | cut -c${#FIRMDIR}- | md_row | tee -a $FILE)
    md_tbl "passfile" "$text"
done

msg ""
msg "## Unix-MD5 hashes"
egrep -sro '\$1\$\w{8}\S{23}' $FIRMDIR | tee -a $FILE
msg ""
if [[ -d "$FIRMDIR/etc/ssl" ]]; then
    msg "### List etc/ssl directory"
    text=$(ls -l $FIRMDIR/etc/ssl | md_row | tee -a $FILE)
    md_tbl "ssl dir" "$text"
fi

msg ""
msg "## SSL related files"
getArray "data/sslfiles"
sslfiles=("${array[@]}")
for sslfile in ${sslfiles[@]}
do
    msg "### $sslfile"
    text=""
       certfiles=( $(find ${FIRMDIR} -name ${sslfile}) )
       : "${certfiles:=empty}"
       if [ "${certfiles##*.}" = "crt" ]; then
          for certfile in "${certfiles[@]}"
          do
             text+=$($certfile | cut -c${#FIRMDIR}- | md_row | tee -a $FILE)
             serialno=$(openssl x509 -in $certfile -serial -noout)
             text+=($serialno | md_row | tee -a $FILE)
             # Perform Shodan search. This assumes Shodan CLI installed with an API key. Uncomment following three lines if you wish to use.
             # serialnoformat=(ssl.cert.serial:${serialno##*=})
             # shocount=$(shodan count $serialnoformat)
             # echo "Number of devices found in Shodan =" $shocount | tee -a $FILE
             text+=(cat $certfile | md_row | tee -a $FILE)
          done
       fi
    md_tbl "ssl file" "$text"
done

msg ""
msg "## SSH related files"
getArray "data/sshfiles"
sshfiles=("${array[@]}")
for sshfile in ${sshfiles[@]}
do
    msg "### $sshfile"
    text=$(find $FIRMDIR -name $sshfile | cut -c${#FIRMDIR}- | md_row | tee -a $FILE)
    md_tbl "ssh file" "$text"
done

msg ""
msg "## configuration files"
getArray "data/conffiles"
conffiles=("${array[@]}")
for conffile in ${conffiles[@]}
do
    msg "### $conffile"
    text=$(find $FIRMDIR -name $conffile | cut -c${#FIRMDIR}- | md_row | tee -a $FILE)
    md_tbl "conf file" "$text"
done
msg ""
msg "## database related files"
getArray "data/dbfiles"
dbfiles=("${array[@]}")
for dbfile in ${dbfiles[@]}
do
    msg "### $dbfile"
    text=$(find $FIRMDIR -name $dbfile | cut -c${#FIRMDIR}- | md_row | tee -a $FILE)
    md_tbl "db file" "$text"
done

msg ""
msg "## shell scripts"
msg "### shell scripts"
text=$(find $FIRMDIR -name "*.sh" | cut -c${#FIRMDIR}- | md_row | tee -a $FILE)
md_tbl "shell script" "$text"

msg ""
msg "## other .bin files"
msg "### bin files"
text=$(find $FIRMDIR -name "*.bin" | cut -c${#FIRMDIR}- | md_row | tee -a $FILE)
md_tbl "bin file" "$text"

msg ""
msg "## patterns in files"
getArray "data/patterns"
patterns=("${array[@]}")
for pattern in "${patterns[@]}"
do
    msg "### $pattern"
    text=$(grep -lsirn $FIRMDIR -e "$pattern" | cut -c${#FIRMDIR}- | md_row | tee -a $FILE)
    md_tbl "$pattern" "$text"
done

msg ""
msg "## web servers"
getArray "data/webservers"
webservers=("${array[@]}")
for webserver in ${webservers[@]}
do
    msg "### $webserver"
    text=$(find $FIRMDIR -name "$webserver" | cut -c${#FIRMDIR}- | md_row | tee -a $FILE)
    md_tbl "$webserver" "$text"
done

msg ""
msg "## important binaries"
getArray "data/binaries"
binaries=("${array[@]}")
for binary in "${binaries[@]}"
do
    msg "### $binary"
    text=$(find $FIRMDIR -name "$binary" | cut -c${#FIRMDIR}- | md_row | tee -a $FILE)
    md_tbl "$binary" "$text"
done

msg ""
msg "## ip addresses"
text=$(grep -sRIEho '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $FIRMDIR | sort | uniq |  md_row | tee -a $FILE)
md_tbl "ip addr" "$text"

msg ""
msg "## urls"
text=$(grep -sRIEoh '(http|https)://[^/"]+' $FIRMDIR | sort | uniq | md_row | tee -a $FILE)
md_tbl "url" "$text"

msg ""
msg "## emails"
text=$(grep -sRIEoh '([[:alnum:]_.-]+@[[:alnum:]_.-]+?\.[[:alpha:].]{2,6})' "$@" $FIRMDIR | sort | uniq |  md_row | tee -a $FILE)
md_tbl "email" "$text"

#Perform static code analysis 
msg "## ESLint"
text=$(eslint -c eslintrc.json $FIRMDIR | sed "s#$FIRMDIR#/#" | md_row | tee -a $FILE)
md_tbl "ESLint" "$text"

msg "## strings"
msg "(coming soon...)"
