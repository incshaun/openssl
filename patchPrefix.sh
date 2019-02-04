PREFIX=VR_

candidatelibs="openssl/libssl.a openssl/libcrypto.a"

for cl in $candidatelibs
do
  # replace longest symbols first, to ensure everything gets at least one prefix
  extsyms=`nm $cl | grep " T " | cut -f3 -d' ' | grep -v $PREFIX | awk '{ print length($0) " " $0; }' | sort -r -n | cut -d ' ' -f 2-` 

  for sym in $extsyms
    do
      echo $sym
      find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/$sym/$PREFIX$sym/g" {} \;
    done
done

# duplicate PREFIXes arise from replacing symbols that are substrings of other symbols.
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/$PREFIX$PREFIX/$PREFIX/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/$PREFIX$PREFIX/$PREFIX/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/$PREFIX$PREFIX/$PREFIX/g" {} \;

# More complex issues arise when substring is internal to another string. Just resolve these manually.
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_ISSUING_VR_DIST_POINT_free/VR_ISSUING_DIST_POINT_free/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/EST_ENG_OPENSSL_VR_RC4/EST_ENG_OPENSSL_RC4/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/TEST_VR_RC4_KEY_SIZE/TEST_RC4_KEY_SIZE/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/TEST_VR_RC4_KEY/TEST_RC4_KEY/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/TEST_ENG_OPENSSL_VR_RC4_P_INIT/TEST_ENG_OPENSSL_VR_RC4_P_INIT/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_dVR_/VR_d/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_DVR_TLS/VR_DTLS/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_do_VR_ssl3_write/VR_do_ssl3_write/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_DTLS_VR_RECORD_LAYER_clear/VR_DTLS_RECORD_LAYER_clear/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_SSL_VR_/VR_SSL_/g" {} \;

find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_X509_subject_VR_name_cmp/VR_X509_subject_name_cmp/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_X509_issuer_VR_name_cmp/VR_X509_issuer_name_cmp/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR__VR_CONF/VR__CONF/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_TS_VR_CONF/VR_TS_CONF/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_PKCS5_PBKDF2_VR_HMAC_VR_SHA1/VR_PKCS5_PBKDF2_HMAC_SHA1/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_PKCS5_PBKDF2_VR_HMAC/VR_PKCS5_PBKDF2_HMAC/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_PEM_write_bio_VR_/VR_PEM_write_bio_/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_NVR_CONF/VR_NCONF/g" {} \;



find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_ECVR_DSA_/VR_ECDSA_/g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/VR_ECVR_DH_compute_key/VR_ECDH_compute_key/g" {} \;

find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s///g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s///g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s///g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s///g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s///g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s///g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s///g" {} \;
find openssl/ \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s///g" {} \;

# Manual fix ups and others. If a new prefix is needed, worth replacing the current one rather than reusing this
# process. Beware of existing occurences of the prefix string in the original package.
# include/openssl/asn1.h
# include/openssl/pem.h
find . \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/x509_/VR_x509_/g" {} \;
find . \( -name '*.c' -or -name '*.h' -or -name '*.num' -or -name '*.pl' -or -name '*.conf' -or -name '*.h.in' -or -name '*.S' -or -name '*.s' \) -exec sed -i -e "s/internal\/VR_/internal\//g" {} \;

