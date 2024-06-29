import sys

text = open(sys.argv[1],'rb').read()
text = text.hex()


hex_string = text
key = "testkey"

# Convert the hexadecimal string to bytes
hex_bytes = bytes.fromhex(hex_string)

# Convert the key to bytes (in Python 3, bytes are used for this purpose)
key_bytes = bytes(key, 'utf-8')

# Perform XOR operation with the key
xored_bytes = bytearray(len(hex_bytes))
hex_array = []

for i in range(len(hex_bytes)):
    hex_array.append(hex_bytes[i])
    current = hex_bytes[i]
    current_key = key_bytes[i % len(key_bytes)]
    xored_bytes[i] = current ^ current_key
    

# Print the result as a hexadecimal string

if ("array" in sys.argv[2]):
	print('payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in xored_bytes) + ' };')
elif ("file" in sys.argv[2]):
	f = open("encrypted_payload.ico", "wb")
	f.write(xored_bytes)

#print(xored_bytes)
