#!/usr/bin/env bash

# Print out the components of a private key to standard output.
check_rsa_key() {
    openssl rsa -in "${1}" -check -text -noout
}

# Print out the key length from a private key.
check_rsa_key_length() {
    openssl rsa -in "${1}" -text -noout | grep "Private-Key"
}

# Check a CSR.
check_csr() {
    openssl req -text -noout -verify -in "${1}"
}

# Check a certificate.
check_certificate() {
    openssl x509 -in "${1}" -noout -text
}

# Print out the key length used for the certificate.
check_certificate_key_length() {
    openssl x509 -in "${1}" -text -noout | grep "Public-Key"
}

# Fingerprinting a certificate.
fingerprint_certificate() {
    openssl x509 -fingerprint -noout -in "${1}" -"${2}"
}

# Expiration date.
check_validity_date_certificate() {
    openssl x509 -noout -dates -in "${1}"
}

# Print out the issuer name (the Issuer is the intermediate CA).
check_issuer_certificate() {
    openssl x509 -noout -issuer -in "${1}"
}

# Print out the subject name (the Subject refers to the certificate itself).
check_subject_certificate() {
    openssl x509 -noout -subject -in "${1}"
}

# Print out the modulus of the public key contained in the certificate.
modulus_certificate() {
    openssl x509 -noout -modulus -in "${1}" | openssl md5
}

# Print out the modulus of the public key contained in the private key.
modulus_rsa_key() {
    openssl rsa -noout -modulus -in "${1}" | openssl md5
}

# Print out the modulus of the public key contained in the request.
modulus_request() {
    openssl req -noout -modulus -in "${1}" | openssl md5
}

# Output the public part of a private key.
print_rsa_public_part() {
    openssl rsa -in "${1}" -pubout -out "${2}"
}

# Output the public part of a private key in RSAPublicKey format.
print_rsa_public_part_rsa_format() {
    openssl rsa -in "${1}" -RSAPublicKey_out -out "${2}"
}
# Encrypt a private key using the given encrypt option.
encrypt_rsa_key() {
    openssl rsa -in "${1}" -"${2}" -out "${3}"
}
# To remove the pass phrase on an RSA private key.
decrypt_rsa_key() {
    openssl rsa -in "${1}" -out "${2}"
}

# Convert a private key from PEM to the given format.
convert_rsa_key() {
    openssl rsa -in "${1}" -outform "${2}" -out "${3}"
}

# Generate a private key using the given encrypt option.
generate_rsa_key() {
    openssl genpkey -"${1}" -algorithm RSA -out "${2}" -pkeyopt rsa_keygen_bits:"${3}"
}

# Generate a certificate request from a private key.
generate_csr() {
    openssl req -key "${1}" -new -out "${2}"
}

# Generate a certificate request from a config file.
generate_csr_from_config_file() {
    openssl req -config "${1}" -key "${2}" -new -out "${3}"
}

# Generate a request from an existing certificate.
generate_csr_from_crt() {
    openssl x509 -x509toreq -in "${1}" -out "${2}" -signkey "${3}"
}

# Generate a self-signed certificate from a given CSR.
generate_self_signed_certificate() {
    openssl x509 -signkey "${1}" -in "${2}" -req -days 365 -out "${3}"
}

# Generate a signed certificate from a request.
generate_signed_certificate() {
    openssl x509 -req -in "${1}" -out "${2}" -CA "${3}" -CAkey "${3}" -CAcreateserial -CAserial "${4}"
}
case "$1" in
    check_rsa_key)
        check_rsa_key "$2"
        ;;
    check_rsa_key_length)
        check_rsa_key_length "$2"
        ;;
    check_certificate_key_length)
        check_certificate_key_length "$2"
        ;;
    check_csr)
        check_csr "$2"
        ;;
    check_certificate)
        check_certificate "$2"
        ;;
    fingerprint_certificate)
        fingerprint_certificate "${@:2}"
        ;;
    check_validity_date_certificate)
        check_validity_date_certificate "${@:2}"
        ;;
    check_issuer_certificate)
        check_issuer_certificate "${@:2}"
        ;;
    check_subject_certificate)
        check_subject_certificate "${@:2}"
        ;;
    modulus_rsa_key)
        modulus_rsa_key "$2"
        ;;
    modulus_request)
        modulus_request "$2"
        ;;
    modulus_certificate)
        modulus_certificate "$2"
        ;;
    print_rsa_public_part)
        print_rsa_public_part "${@:2}"
        ;;
    print_rsa_public_part_rsa_format)
        print_rsa_public_part_rsa_format "${@:2}"
        ;;
    encrypt_rsa_key)
        encrypt_rsa_key "${@:2}"
        ;;        
    decrypt_rsa_key)
        decrypt_rsa_key "${@:2}"
        ;;
    convert_rsa_key)
        convert_rsa_key "${@:2}"
        ;;        
    generate_rsa_key)
        generate_rsa_key "${@:2}"
        ;;
    generate_csr)
        generate_csr "${@:2}"
        ;;
    generate_csr_from_config_file)
        generate_csr_from_config_file "${@:2}"
        ;;
    generate_csr_from_crt)
        generate_csr_from_crt "${@:2}"
        ;;
    generate_self_signed_certificate)
        generate_self_signed_certificate "${@:2}"
        ;;
    generate_signed_certificate)
        generate_signed_certificate "${@:2}"
        ;;
    *)
    echo "Unknown command"
    exit 1
esac