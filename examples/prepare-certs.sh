#/bin/bash

help()
{
   echo ""
   echo "Usage: $0 -p idPrefix -n idNum"
   echo "\t-p prefix of identities"
   echo "\t-n numbers of identities created under idPrefix"
   echo "\t-d directory to write ndncert files"
   echo "\t-D delete identities from keychain"
   echo "\t-h print this help message"
   exit 1
}

delete=0
while getopts "p:n:d:D" opt
do
   case "$opt" in
      p ) idPrefix="$OPTARG" ;;
      n ) idNum="$OPTARG" ;;
      d ) dir="$OPTARG" ;;
      D ) delete=1 ;;
      h ) help ;;
      ? ) help ;;
   esac
done

if [ $# -le 4 -a $delete -eq 0 ] 
then 
    help
    exit 1
fi

if [ $delete -eq 1 ]
then
    for i in `seq 1 $idNum`
    do  
        identity=$idPrefix$i
        if ndnsec get-default -c -i $identity  &>/dev/null
        then
        echo "deleting $identity"
        ndnsec delete $identity
        fi
    done
    exit 1
fi

if [ ! -d "$dir" ]; then
    echo "creating $dir"
    mkdir $dir
fi

for i in `seq 1 $idNum`
do  
    identity=$idPrefix$i
    if ! ndnsec get-default -c -i $identity 2>/dev/null
    then
        echo "creating $identity"
        ndnsec key-gen $identity | ndnsec cert-install -
    fi
    ndnsec cert-dump -i $identity > $dir/$i.ndncert
done