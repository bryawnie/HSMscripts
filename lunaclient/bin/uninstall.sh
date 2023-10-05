#!/bin/bash
#**********************************************************************************
#
# FileName: crypto/builds/client/unix/common
#
# Description: *Nix client install/uninstall
#
# Copyright © 2016-17 SafeNet. All rights reserved.
#
# This file contains information that is proprietary to SafeNet and may not be
# distributed or copied without written consent from SafeNet.
#
#**********************************************************************************

case "`echo 'x\c'`" in 'x\c')
	                       echo="echo -n"
	                       nnl= ;;       
                           
                           x)      
                           echo="echo"      
                           nnl="\c" ;;   
                           
esac

# The correct value based on product release will be set accordingly during
# the installation by the "install.sh"
LUNA_CLIENT_STR="Luna HSM Client"

display_uninstall_parameters() {
    echo ""
    echo "   help   - Display uninstall options"
    echo "   all    - Complete $LUNA_CLIENT_STR uninstall"
    echo "   jsp    - Luna JSP (Java)"
    echo "   sdk    - Luna SDK"
    echo "   util   - Utilities"
    echo "   driver - Drivers"
    echo ""
}

display_uninstall_help() {
    echo ""
#    echo "usage: $0 [help|all|jsp|sdk|util|driver]"
#    display_uninstall_parameters
    echo "usage: $0 [help]"
}

display_usage() {
    echo ""
    echo "Invalid option: $1"
    echo ""
#    echo "usage: $0 [help|all|jsp|sdk|util|driver]"
#    display_uninstall_parameters
    echo "usage: $0 [help]"
}

prompt_yes_no() {
    rsp=""
    while [ "$rsp" != "y" ] && [ "$rsp" != "n" ] && [ "$rsp" != "yes" ] && [ "$rsp" != "no" ]
    do
        $echo "$1 ${nnl}"
        read rsp
    done;
    
    if [ "$rsp" = "y" ] || [ "$rsp" = "yes" ] ; then
        return 0
    fi
    
    return 1
}

# confirm_uninstall() {
#     echo ""
#     echo "Complete $LUNA_CLIENT_STR uninstall has been selected."
#     echo ""
#     echo "Select 'yes' or 'y' to proceed with the Complete uninstall."
#     echo ""
#     echo "Select 'no' or 'n', to cancel this uninstall and try again with different"
#     echo "uninstall parameters."
#     echo ""

#     prompt_yes_no "Continue (y/n)?"

#     if [ $? -eq 0 ]; then
#         echo ""
#     else
#         echo ""
#         echo "Run uninstall.sh and select the appropriate feature to uninstall:"
#         display_uninstall_parameters
#         exit 1
#     fi
# }
confirm_uninstall() {
    echo ""
    echo "$LUNA_CLIENT_STR will be completely uninstalled."
    echo ""
    echo "Enter 'yes' or 'y' to proceed."
    echo ""
    echo "Enter 'no' or 'n', to cancel the uninstall."
    echo ""

    prompt_yes_no "Continue (y/n)?"

    if [ $? -eq 0 ]; then
        echo ""
    else
        echo ""
        echo "Uninstall aborted."
        exit 1
    fi
}


# Change to the directory where the script is
FULL_PATH=`echo $0 | sed -e "s/\(.*\)\/.*/\1/"`
if [ "$FULL_PATH" != "$0" ] ; then
    cd $FULL_PATH
fi

if [ "$1" = "help" ] ; then
    display_uninstall_help
    exit 0
fi


if [ "$1" = "" ] ; then
    confirm_uninstall
else
    display_uninstall_help
    exit 1
fi

first_param="remove_feature"

# KB: Keeping the following and all other feature specific just in case we decide
# later on to try to uninstall products and components
case "$1" in
    "")
    first_param="remove_client"
    ;;

    all|ALL)
    first_param="remove_client"
    ;;

    jsp|JSP)
    ;;
    
    sdk|SDK)
    ;;
    
    util|UTIL)
    ;;
    
    driver|DRIVER)
    ;;

    *)
    display_usage "$1"
    exit 1
    ;;
esac

INSTALLED_BY_ROOT=0
[ "$(id -u)" -eq "0" ] &> /dev/null
IS_ROOT_USER=$?
# If installed by root and we not root, fail the uninstall.
if [ $INSTALLED_BY_ROOT -eq 0 ] && [ $IS_ROOT_USER -eq 1 ] ; then
    echo "This installation has been installed by root."
    echo "To uninstall, please run this uninstall.sh as root."
fi

# Uninstall
/bin/bash common $first_param $1

