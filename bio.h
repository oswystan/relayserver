/*
 **************************************************************************************
 *       Filename:  bio.h
 *    Description:   header file
 *
 *        Version:  1.0
 *        Created:  2018-02-17 10:56:16
 *
 *       Revision:  initial draft;
 **************************************************************************************
 */

#ifndef BIO_H_INCLUDED
#define BIO_H_INCLUDED

#include <openssl/bio.h>
extern "C" BIO_METHOD *BIO_dtls_filter(void);

#endif /*BIO_H_INCLUDED*/

/********************************** END **********************************************/

