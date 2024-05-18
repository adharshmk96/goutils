keys:
	mkdir -p .keys
	openssl ecparam -genkey -name secp521r1 -noout -out .keys/ecdsa-private.pem
	openssl ec -in .keys/ecdsa-private.pem -pubout -out .keys/ecdsa-public.pem