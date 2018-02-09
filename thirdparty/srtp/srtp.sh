#!/usr/bin/env bash
###########################################################################
##                     Copyright (C) 2018 wystan
##
##       filename: srtp.sh
##    description:
##        created: 2018-02-09 17:36:42
##         author: wystan
##
###########################################################################


function _start() {
    echo "==> start $1 ..."
    echo "-------------------------------------------"
}

function _end() {
    [[ $1 -ne 0 ]] && printf -- '**************** FAILED *******************\n\n' && exit $1
    [[ $1 -eq 0 ]] && printf -- '---------------- SUCCESS ------------------\n\n'
}

function do_download() {
    _start "downloading"
        cur_dir=`pwd`
        git clone https://github.com/cisco/libsrtp && \
        cd libsrtp && \
        git checkout -b local_dev v2.1.0 && \
        cd $cur_dir
    _end $?
}

function do_mk() {
    _start "building"
        cur_dir=`pwd`
        cd libsrtp && \
        set -eu && \
        ./configure --prefix=$cur_dir && \
        make -j4 && \
        make install && \
        cd $cur_dir
    _end $?
}

###########################################################################
do_download
do_mk
