module SecretSharing
	class Shamir
		attr_reader :n, :k, :secret

		def initialize(n, k=n)
			if k > n then
				raise ArgumentError, 'k must be smaller or equal than n'
			end	
			@n = n
			@k = k
			@secret = nil
			@shares = []
		end

		def secret_set?
			! @secret.nil?
		end
	end
end
