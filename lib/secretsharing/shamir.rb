module SecretSharing
	class Shamir
		attr_reader :n, :k, :secret

		def initialize(n, k=n)
			@n = n
			@k = k
			@secret = nil
		end

		def secret_set?
			! @secret.nil?
		end
	end
end
