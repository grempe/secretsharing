require 'openssl'
require 'digest/sha1'

module SecretSharing
	class Shamir
		attr_reader :n, :k, :secret, :secret_bitlength, :shares

		DEFAULT_SECRET_BITLENGTH = 256

		def initialize(n, k=n)
			if k > n then
				raise ArgumentError, 'k must be smaller or equal than n'
			end	
			if k < 2 then
				raise ArgumentError, 'k must be greater or equal to two'
			end
			@n = n
			@k = k
			@secret = nil
			@shares = []
			@received_shares = []
		end

		def secret_set?
			! @secret.nil?
		end

		def create_random_secret(bitlength = DEFAULT_SECRET_BITLENGTH)
			raise 'secret already set' if secret_set?
			@secret = get_random_number(bitlength)
			@secret_bitlength = bitlength
			create_shares
                        @secret
		end

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

		def construct_share(x, bitlength)
			p_x = evaluate_polynomial_at(x)
			SecretSharing::Shamir::Share.new(x, p_x, @prime, bitlength)
		end

		def evaluate_polynomial_at(x)
			result = OpenSSL::BN.new('0')
			@coefficients.each_with_index do |coeff, i|
				result += coeff * OpenSSL::BN.new(x.to_s)**i
				result %= @prime
			end
			result
		end

		def recover_secret
			@secret = OpenSSL::BN.new('0')
			@received_shares.each do |share|
				summand = share.y * l(share.x, @received_shares)
				summand %= share.prime
				@secret += summand
				@secret %= share.prime
			end
		end
		
		# this is l_j(0), i.e.
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

	class SecretSharing::Shamir::Share
		attr_reader :x, :y, :prime_bitlength, :prime

                FORMAT_VERSION = '0'

		def initialize(x, y, prime, prime_bitlength)
			@x = x
			@y = y
			@prime = prime
			@prime_bitlength = prime_bitlength
		end

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
