from poseidon_hash import poseidon_hash
import os
import time



def key_hex_to_poseidon_digest(key_hex: str) -> int:
    key_bytes = bytes.fromhex(key_hex)
    if len(key_bytes) != 16:
        raise ValueError("expected a 16-byte key (32 hex chars)")

    key_int = int.from_bytes(key_bytes, "little")
    key_fp8 = convert_uint2040_to_Fp(key_int)
    digest = poseidon_hash(key_fp8)
    return digest

# turn string array to uint2040 array
# i.e. "abc" = 97+98*256+99*65536 = 6513249
# each string is 255byte, so each integer will be uint2040 (255*8=2040)
def string_array_to_uint2040_array(set_input):
	set_bytes = []
	for item in set_input:
		element_byte = bytes(item,'utf-8')
		set_bytes.append(int.from_bytes(element_byte, "little"))

	return set_bytes

# turn a string to padded uint_8[255] array (byte array)
def string_to_padded_uint8_array(input_string):
	bytes_array = bytes(input_string,'utf-8')
	padded_int_array =[]
	length = len(bytes_array)
	for i in range(0, 255):
		if (i < length):
			padded_int_array.append(bytes_array[i])
		else:
			padded_int_array.append(0)
	return padded_int_array

# covert large integer to Fp[8] array, each is 253bit limb
# note: Though input is uint2040, valid input will only be 2024bit (253bytes)!!! 
def convert_uint2040_to_Fp(long_input):
	Fp_array = []
	for i in range(0,8):
		Fp_array.append(long_input%(1<<252))
		long_input >>= 253
	print(Fp_array)
	return Fp_array

# convert a large integer array to Fp[8] array
# i.e. each uint2040 will be Fp[8]
def convert_uint2040_array_to_Fp8_array(set_input):
	Fp_array = []
	for element in set_input:
		Fp_array.append(convert_uint2040_to_Fp(element))

	return Fp_array

# Fp[8] input for Poseidon hash
def Fp8_to_hash(Fp_array):
	output_hash = []
	start = time.time()
	print("compute Fp8 to hash")
	for element in Fp_array:
		output_hash.append(poseidon_hash(element))
	end = time.time()
	print("Fp8 to hash time", end-start)

	return output_hash


# compute the length of common substring
def string_common_len(string1, string2):
	length = min(len(string1), len(string2))

	for i in range(0, length):
		if string1[i]==string2[i]:
			continue
		else:
			return i
	return length




return_value = key_hex_to_poseidon_digest("771591d4e3299253e5455fdb21004750")
print(return_value)

