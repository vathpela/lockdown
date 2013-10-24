#!/bin/bash

makeit() {
    esl=$1 && shift
    filename=$1 && shift
    varname=$1 && shift
    
    echo ./buildvar -d ${esl}.esl -t \"Fri Oct 18 13:55:00 2013\" \
        -o ${filename}.unsigned -a ${filename}.authattr -n ${varname} \
        -N -B -R --force
    ./buildvar -d ${esl}.esl -t "Fri Oct 18 13:55:00 2013" \
        -o ${filename}.unsigned -a ${filename}.authattr -n ${varname} \
        -N -B -R --force
    echo openssl dgst -sha256 -sign \
        ${esl}.key \> ${filename}.sig \< ${filename}.authattr
    openssl dgst -sha256 -sign \
        ${esl}.key > ${filename}.sig < ${filename}.authattr
    echo ./assemble -n ${varname} -s ${filename}.unsigned -a ${filename}.authattr \
        -c ${esl}.cer -S ${filename}.sig -o ${filename}.auth
    ./assemble -n ${varname} -s ${filename}.unsigned -a ${filename}.authattr \
        -c ${esl}.cer -S ${filename}.sig -o ${filename}.auth
}

SIGNER=ca

echo certutil -d /etc/pki/pesign -n ${SIGNER} -L -r \> ${SIGNER}.cer
certutil -d /etc/pki/pesign -n ${SIGNER} -L -r > ${SIGNER}.cer
echo openssl x509 -in ${SIGNER}.cer -inform DER -out ${SIGNER}.crt -outform PEM
openssl x509 -in ${SIGNER}.cer -inform DER -out ${SIGNER}.crt -outform PEM
echo pk12util -o ${SIGNER}.p12 -n ${SIGNER} -d /etc/pki/pesign/
pk12util -o ${SIGNER}.p12 -n ${SIGNER} -d /etc/pki/pesign/
echo openssl pkcs12 -in ${SIGNER}.p12 -out ${SIGNER}.key
openssl pkcs12 -in ${SIGNER}.p12 -out ${SIGNER}.key
~/devel/kernel.org/efitools/cert-to-efi-sig-list ${SIGNER}.crt ${SIGNER}.esl

makeit ${SIGNER} PK PK
makeit ${SIGNER} KEK KEK
makeit ${SIGNER} DB db

# ./buildvar -d PK.esl -t "Fri Oct 18 13:55:00 2013" -o PK.unsigned -a PK.authattr -n PK -N -B -R --force
# ./buildvar -d PK.esl -t "Fri Oct 18 13:55:00 2013" -o KEK.unsigned -a KEK.authattr -n KEK -N -B -R --force
# ./buildvar -d PK.esl -t "Fri Oct 18 13:55:00 2013" -o DB.unsigned -a DB.authattr -n db -N -B -R --force
# openssl dgst -sha256 -sign PK.key  > KEK.sig < KEK.authattr 
# openssl dgst -sha256 -sign PK.key  > PK.sig < PK.authattr 
# openssl dgst -sha256 -sign PK.key  > DB.sig < DB.authattr 
# ./assemble -n KEK -s KEK.unsigned -a KEK.authattr -c PK.cer -S KEK.sig -o KEK.auth
# ./assemble -n db -s DB.unsigned -a DB.authattr -c PK.cer -S DB.sig -o DB.auth
# ./assemble -n PK -s PK.unsigned -a PK.authattr -c PK.cer -S PK.sig -o PK.auth
# 
