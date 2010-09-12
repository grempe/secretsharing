require 'openssl'

module SecretSharing
	class Shamir
		attr_reader :n, :k, :secret, :secret_bitlength, :shares

		DEFAULT_SECRET_BITLENGTH = 128

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
		end

		def secret_set?
			! @secret.nil?
		end

		def create_random_secret(bitlength = DEFAULT_SECRET_BITLENGTH)
			raise RuntimeError, 'secret already set' if secret_set?
			@secret = get_random_number(bitlength)
			@secret_bitlength = bitlength
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
	end
end
