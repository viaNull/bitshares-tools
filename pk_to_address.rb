## convert BTS public key to address
# Useful link:
# http://lenschulwitz.com/base58
# https://bitsharestalk.org/index.php?topic=24454.0


# In Graphene, public key cryptography uses the same elliptic curve as Bitcoin, i. e. secp256k1. It even uses the same implementation.
# A public key is just a point on the curve. This can be represented as two 256-bit numbers, or due to curve symmetry as a single 256-bit number plus a flag. In order to distinguish the formats, the key is prefixed with '04' byte in the first case (called "uncompressed format"), and, depending on the flag value, with a '02' or '03' byte in the second case (called "compressed format").
# To construct a Graphene address from a public key, these steps need to be applied:

# 1. You need the 33 bytes making up the compressed representation of the public key CPK.
# 2. Compute the hash H1 = SHA512(CPK).
# 3. Compute the hash H2 = RIPEMD160(H1).
# 4. Compute the hash H3 = RIPEMD160(H2).
# 5. Take the last 4 bytes from the hash value H3 as checksum CS.   ===> FIX: first 4 bytes !!
# 6. Append CS to H2.
# 7. Transform the result into base58 format.
# 8. Prepend the network address prefix, i.e. "BTS" for BitShares.

# In BitShares, like in Bitcoin, addresses are used to indicate required authorization for performing operations on certain objects. The similarity ends at this abstract level, though.

require "base58"
require "digest"

owner_public_key = "BTS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"

p t1 = owner_public_key[3..-1]  # remove prefix

# bitcoin base58 decode
p t2 = Base58.decode(t1,:bitcoin).to_s(16)  ## decode address to binary (as hex) 

p cpk = t2[0..-9]  #remove check length 8  ,get length 66 string (that is: 33 bytes)

cpk = "0"+cpk if cpk.length == 65  # 怀疑是gem base58 bug

p cpk
p h1 = Digest::SHA512.hexdigest([cpk].pack("H*"))

p h2 = Digest::RMD160.hexdigest([h1].pack("H*"))

p h3 = Digest::RMD160.hexdigest([h2].pack("H*"))

cs = h3[0..7] 
# p cs = h3[-8..-1]

p result = h2+cs

t3 = Base58.encode(result.hex ,:bitcoin)

address = "BTS" + t3

puts "-----------------------"
puts "Address is : #{address}"  # Got "BTSFAbAx7yuxt725qSZvfwWqkdCwp9ZnUama"

