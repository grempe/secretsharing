require 'openssl'
require 'digest/sha1'

module SecretSharing
	# The SecretSharing::Shamir class can be used to share random
	# secrets between n people, so that k < n people can recover the
	# secret, but k-1 people learn nothing (in an information-theoretical
	# sense) about the secret.
	#
	# For a theoretical background, see 
	# http://www.cs.tau.ac.il/~bchor/Shamir.html or
	# http://en.wikipedia.org/wiki/Secret_sharing#Shamir.27s_scheme
	#
	# To share a secret, create a new SecretSharing::Shamir object and
	# then call the create_random_secret() method. The secret is now in
	# the secret attribute and the shares are an array in the shares attribute.
	class Shamir
		attr_reader :n, :k, :secret, :secret_bitlength, :shares

		DEFAULT_SECRET_BITLENGTH = 256

		# To create a new SecretSharing::Shamir object, you can
		# pass either just n, or k and n.
		#
		# For example:
		#   s = SecretSharing::Shamir.new(5, 3)
		# to create an object for 3 out of 5 secret sharing.
		#
		# or
		#   s = SecretSharing::Shamir.new(3)
		# for 3 out of 3 secret sharing.
		def initialize(n, k=n)
			if k > n then
				raise ArgumentError, 'k must be smaller or equal than n'
			end	
			if k < 2 then
				raise ArgumentError, 'k must be greater or equal to two'
			end
			if n > 255 then
				raise ArgumentError, 'n must be smaller than 256'
			end
			@n = n
			@k = k
			@secret = nil
			@shares = []
			@received_shares = []
		end

		# Check whether the secret is set.
		def secret_set?
			! @secret.nil?
		end

		# Create a random secret of a certain bitlength. Returns the
		# secret and stores it in the 'secret' attribute.
		def create_random_secret(bitlength = DEFAULT_SECRET_BITLENGTH)
			raise 'secret already set' if secret_set?
			raise 'max bitlength is 1024' if bitlength > 1024
			@secret = get_random_number(bitlength)
			@secret_bitlength = bitlength
			create_shares
			@secret
		end

		# Add a secret share to the object. Accepts but a SecretSharing::Shamir::Share
		# instance or a string representing one. Returns true if enough shares have
		# been added to recover the secret, false otherweise.
		def <<(share)
			# convert from string if needed
			if share.class != SecretSharing::Shamir::Share then
				if share.class == String then
					share = SecretSharing::Shamir::Share.from_string(share)
				else
					raise ArgumentError 'SecretSharing::Shamir::Share or String needed'
				end
			end
			if @received_shares.include? share then
				raise 'share has already been added'
			end
			if @received_shares.length == @k then
				raise 'we already have enough shares, no need to add more'
			end
			@received_shares << share
			if @received_shares.length == @k then
				recover_secret
				return true
			end
			false
		end

		# Computes the smallest prime of a given bitlength. Uses prime_fasttest
		# from the OpenSSL library with 20 attempts to be compatible to openssl
		# prime, which is used in the OpenXPKI::Crypto::Secret::Split library.
		def self.smallest_prime_of_bitlength(bitlength)
			# start with 2^bit_length + 1
			test_prime = OpenSSL::BN.new((2**bitlength + 1).to_s)	
			prime_found = false
			while (! prime_found) do
				# prime_fasttest? 20 do be compatible to
				# openssl prime, which is used in OpenXPKI::Crypto::Secret::Split
				prime_found = test_prime.prime_fasttest? 20
				test_prime += 2
			end
			test_prime
		end

		private
		# Creates a random number of a certain bitlength, optionally ensuring the
		# bitlength by setting the highest bit to 1.
		def get_random_number(bitlength, highest_bit_one = true)
			byte_length = (bitlength / 8.0).ceil
			rand_hex = OpenSSL::Random.random_bytes(byte_length).each_byte.to_a.map { |a| "%02x" % a }.join('')
			rand = OpenSSL::BN.new(rand_hex, 16)
			begin
				rand.mask_bits!(bitlength)
			rescue OpenSSL::BNError
				# never mind if there was an error, this just means
				# rand was already smaller than 2^bitlength - 1
			end
			if highest_bit_one then
				rand.set_bit!(bitlength)
			end	
			rand
		end

		# Creates the shares by computing random coefficients for a polynomial
		# and then computing points on this polynomial.
		def create_shares
			@coefficients = []
			@coefficients[0] = @secret

			# round up to next nibble
			next_nibble_bitlength = @secret_bitlength + (4 - (@secret_bitlength % 4))
			prime_bitlength = next_nibble_bitlength + 1
			@prime = self.class.smallest_prime_of_bitlength(prime_bitlength)

			# compute random coefficients
			(1..k-1).each do |x|
				@coefficients[x] = get_random_number(@secret_bitlength)
			end

			(1..n).each do |x|
				@shares[x-1] = construct_share(x, prime_bitlength)
			end
		end	

		# Construct a share by evaluating the polynomial at x and creating
		# a SecretSharing::Shamir::Share object.
		def construct_share(x, bitlength)
			p_x = evaluate_polynomial_at(x)
			SecretSharing::Shamir::Share.new(x, p_x, @prime, bitlength)
		end

		# Evaluate the polynomial at x.
		def evaluate_polynomial_at(x)
			result = OpenSSL::BN.new('0')
			@coefficients.each_with_index do |coeff, i|
				result += coeff * OpenSSL::BN.new(x.to_s)**i
				result %= @prime
			end
			result
		end

		# Recover the secret by doing Lagrange interpolation.
		def recover_secret
			@secret = OpenSSL::BN.new('0')
			@received_shares.each do |share|
				summand = share.y * l(share.x, @received_shares)
				summand %= share.prime
				@secret += summand
				@secret %= share.prime
			end
		end
		
		# Part of the Lagrange interpolation.
		# This is l_j(0), i.e.
		# \prod_{x_j \neq x_i} \frac{-x_i}{x_j - x_i}
		# for more information compare Wikipedia:
		# http://en.wikipedia.org/wiki/Lagrange_form
		def l(x, shares)
			shares.select { |s| s.x != x }.map do |s|
				OpenSSL::BN.new((-s.x).to_s) * 
				OpenSSL::BN.new((x - s.x).to_s).mod_inverse(shares[0].prime)
			end.inject { |p, f| p.mod_mul(f, shares[0].prime) }
		end
	end

	# A SecretSharing::Shamir::Share object represents a share in the
	# Shamir secret sharing scheme. The share consists of a point (x,y) on
	# a polynomial over Z/Zp, where p is a prime.
	class SecretSharing::Shamir::Share
		attr_reader :x, :y, :prime_bitlength, :prime

		FORMAT_VERSION = '0'

		# Create a new share with the given point, prime and prime bitlength.
		def initialize(x, y, prime, prime_bitlength)
			@x = x
			@y = y
			@prime = prime
			@prime_bitlength = prime_bitlength
		end

		# Create a new share from a string format representation. For
		# a discussion of the format, see the to_s() method.
		def self.from_string(string)
			version = string[0,1]
			if version != '0' then
				raise "invalid share format version #{version}."
			end
			x = string[1,2].hex
			prime_bitlength = 4 * string[-2,2].hex + 1
			p_x_str = string[3, string.length - 9]
			checksum = string[-6, 4]
			computed_checksum = Digest::SHA1.hexdigest(p_x_str)[0,4].upcase
			if checksum != computed_checksum then
				raise "invalid checksum. expected #{checksum}, got #{computed_checksum}"
			end
			prime = SecretSharing::Shamir.smallest_prime_of_bitlength(prime_bitlength)
			self.new(x, OpenSSL::BN.new(p_x_str, 16), prime, prime_bitlength)
		end

		# A string representation of the share, that can for example be
		# distributed in printed form.
		# The string is an uppercase hexadecimal string of the following
		# format: ABBC*DDDDEEEE, where
		# * A (the first nibble) is the version number of the format, currently
		#   fixed to 0.
		# * B (the next byte, two hex characters) is the x coordinate of the point
		#   on the polynomial.
		# * C (the next variable length of bytes) is the y coordinate of the point
		#   on the polynomial.
		# * D (the next two bytes, four hex characters) is the two highest bytes of
		#   the SHA1 hash on the string representing the y coordinate, it is used as
		#   a checksum to guard against typos
		# * E (the next two bytes, four hex characters) is the bitlength of the prime
		#   number in nibbles.
		def to_s
			# bitlength in nibbles to save space
			prime_nibbles = (@prime_bitlength - 1) / 4 
			p_x = ("%x" % @y).upcase
			FORMAT_VERSION + ("%02x" % @x).upcase \
				+ p_x \
				+ Digest::SHA1.hexdigest(p_x)[0,4].upcase \
				+ ("%02x" % prime_nibbles).upcase
		end
	end	
end
